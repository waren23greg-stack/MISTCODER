"""
MISTCODER -- MOD-08 Binary Lifting Engine
Test Suite v0.1.0

Tests cover:
    -- Format detection (ELF, PE, Mach-O, WASM, raw)
    -- ELF parsing (32/64, LE/BE, sections, security)
    -- PE parsing (PE32/PE32+, DLL characteristics)
    -- Mach-O parsing (32/64, fat, security flags)
    -- WASM parsing (sections, imports, exports)
    -- Raw binary fallback
    -- Security feature detection
    -- Language fingerprinting
    -- Dangerous import detection
    -- High entropy section detection
    -- IR node/edge schema
    -- Finding generation
    -- BinaryLiftingEngine integration
    -- File not found error handling
    -- lift_bytes interface
"""

import os
import sys
import struct
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                "..", "src"))

from binary_lifting import (
    BinaryLiftingEngine,
    ELFParser, PEParser, MachOParser, WASMParser,
    RawBinaryParser, SecurityReportBuilder,
    _shannon_entropy, _extract_strings,
    _safe_unpack, _make_node, _make_edge,
    ELF_MAGIC, PE_MAGIC, WASM_MAGIC,
    DANGEROUS_IMPORTS, HIGH_ENTROPY_THRESHOLD,
    LANG_PATTERNS,
)


# ---------------------------------------------------------------------------
# Minimal binary builders
# ---------------------------------------------------------------------------

def make_minimal_elf64() -> bytes:
    """
    Build a minimal valid ELF64 LE binary header.
    No program headers, no sections. Just enough to parse.
    """
    ident = (
        b"\x7fELF"   # magic
        b"\x02"      # EI_CLASS = 64-bit
        b"\x01"      # EI_DATA  = LE
        b"\x01"      # EI_VERSION
        b"\x00"      # EI_OSABI
        + b"\x00" * 8   # padding
    )
    # e_type=ET_EXEC(2), e_machine=x86_64(0x3E)
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2, 0x3E, 1, 0x400000,   # type, machine, version, entry
        0, 0,                    # phoff, shoff
        0, 64,                   # flags, ehsize
        56, 0,                   # phentsize, phnum
        64, 0, 0                 # shentsize, shnum, shstrndx
    )
    binary = ident + header
    # Pad to at least 128 bytes
    binary += b"\x00" * (128 - len(binary))
    # Add stack canary string
    binary += b"__stack_chk_fail\x00"
    return binary


def make_minimal_elf32() -> bytes:
    ident = (
        b"\x7fELF"
        b"\x01"    # 32-bit
        b"\x01"    # LE
        b"\x01"
        b"\x00"
        + b"\x00" * 8
    )
    header = struct.pack(
        "<HHIIIIIHHHHHH",
        2, 0x03, 1, 0x8048000,  # ET_EXEC, x86
        0, 0,
        0, 52,
        32, 0,
        40, 0, 0
    )
    binary = ident + header
    binary += b"\x00" * (128 - len(binary))
    return binary


def make_minimal_pe() -> bytes:
    # DOS header
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 60, 64)  # e_lfanew = 64

    # PE signature + COFF
    pe_sig = b"PE\x00\x00"
    coff   = struct.pack(
        "<HHIIIHH",
        0x8664,  # x86_64
        0,       # num_sections
        0,       # timestamp
        0,       # sym_table_ptr
        0,       # num_symbols
        0,       # opt_hdr_size
        0x0022,  # characteristics (exe + large)
    )
    binary = bytes(dos) + pe_sig + coff
    binary += b"\x00" * (256 - len(binary))
    return binary


def make_pe_with_security() -> bytes:
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 60, 64)

    pe_sig = b"PE\x00\x00"
    coff   = struct.pack(
        "<HHIIIHH",
        0x8664, 0, 0, 0, 0,
        240,    # opt_hdr_size (standard PE32+)
        0x0022
    )
    # Optional header with DLL characteristics
    # PE32+ magic = 0x20B
    opt_hdr = bytearray(240)
    struct.pack_into("<H", opt_hdr, 0, 0x20B)  # PE32+
    # DLL characteristics at offset 70
    dll_chars = 0x0140   # NX_COMPAT | DYNAMIC_BASE
    struct.pack_into("<H", opt_hdr, 70, dll_chars)

    binary = bytes(dos) + pe_sig + coff + bytes(opt_hdr)
    binary += b"\x00" * (512 - len(binary))
    return binary


def make_minimal_macho64() -> bytes:
    magic     = struct.pack("<I", 0xFEEDFACF)
    cpu_type  = struct.pack("<I", 0x01000007)  # x86_64
    cpu_sub   = struct.pack("<I", 3)
    filetype  = struct.pack("<I", 2)           # MH_EXECUTE
    ncmds     = struct.pack("<I", 0)
    sizeofcmds = struct.pack("<I", 0)
    flags     = struct.pack("<I", 0x00200000)  # MH_PIE
    reserved  = struct.pack("<I", 0)
    binary = (magic + cpu_type + cpu_sub + filetype +
              ncmds + sizeofcmds + flags + reserved)
    binary += b"\x00" * (256 - len(binary))
    return binary


def make_minimal_wasm() -> bytes:
    # WASM magic + version
    header = b"\x00asm" + struct.pack("<I", 1)
    # Empty type section (id=1, size=1, count=0)
    type_sec = bytes([1, 1, 0])
    # Empty export section (id=7, size=1, count=0)
    export_sec = bytes([7, 1, 0])
    return header + type_sec + export_sec


def make_raw_with_dangerous() -> bytes:
    payload  = b"\x90" * 64       # NOP sled
    payload += b"system\x00"      # dangerous import
    payload += b"gets\x00"        # dangerous import
    payload += b"strcpy\x00"
    payload += b"\x00" * 64
    return payload


def make_go_binary_stub() -> bytes:
    return (b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 8 +
            b"\x00" * 48 +
            b"runtime.main\x00"
            b"runtime.goexit\x00"
            b"go.buildid\x00")


def make_rust_binary_stub() -> bytes:
    return (b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 8 +
            b"\x00" * 48 +
            b"core::panicking\x00"
            b"rust_begin_unwind\x00"
            b"__rust_alloc\x00")


def make_high_entropy_section() -> bytes:
    import os as _os
    return _os.urandom(1024)


# ---------------------------------------------------------------------------
# Utility function tests
# ---------------------------------------------------------------------------

class TestUtilityFunctions(unittest.TestCase):

    def test_shannon_entropy_empty(self):
        self.assertEqual(_shannon_entropy(b""), 0.0)

    def test_shannon_entropy_uniform(self):
        # All same byte -- entropy = 0
        self.assertEqual(_shannon_entropy(b"\x00" * 100), 0.0)

    def test_shannon_entropy_max(self):
        # All 256 values equally -- entropy near 8
        data = bytes(range(256))
        self.assertGreater(_shannon_entropy(data), 7.9)

    def test_shannon_entropy_high_random(self):
        import os as _os
        e = _shannon_entropy(_os.urandom(1024))
        self.assertGreater(e, 7.0)

    def test_extract_strings_finds_ascii(self):
        data = b"\x00\x00hello world\x00\x00test123\x00"
        strings = _extract_strings(data, min_len=5)
        values = [s["value"] for s in strings]
        self.assertTrue(any("hello" in v for v in values))

    def test_extract_strings_min_length(self):
        data = b"ab\x00abcdefgh\x00"
        strings = _extract_strings(data, min_len=5)
        for s in strings:
            self.assertGreaterEqual(s["length"], 5)

    def test_extract_strings_has_offset(self):
        data = b"\x00" * 10 + b"hello_world\x00"
        strings = _extract_strings(data, min_len=5)
        self.assertTrue(any(s["offset"] > 0 for s in strings))

    def test_safe_unpack_valid(self):
        data = struct.pack("<HH", 0x1234, 0x5678)
        result = _safe_unpack("<HH", data, 0)
        self.assertEqual(result, (0x1234, 0x5678))

    def test_safe_unpack_out_of_bounds(self):
        data = b"\x00\x01"
        result = _safe_unpack("<I", data, 0)
        self.assertIsNone(result)

    def test_make_node_schema(self):
        n = _make_node("N1", "section", ".text", None,
                       {"size": 1024})
        for key in ("id", "type", "name", "line", "props"):
            self.assertIn(key, n)

    def test_make_edge_schema(self):
        e = _make_edge("N1", "N2", "calls")
        self.assertEqual(e["src"],  "N1")
        self.assertEqual(e["dst"],  "N2")
        self.assertEqual(e["type"], "calls")


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

class TestFormatDetection(unittest.TestCase):

    def setUp(self):
        self.engine = BinaryLiftingEngine()

    def test_detect_elf(self):
        self.assertEqual(
            self.engine._detect_format(ELF_MAGIC + b"\x00" * 4),
            "ELF"
        )

    def test_detect_pe(self):
        self.assertEqual(
            self.engine._detect_format(PE_MAGIC + b"\x00" * 4),
            "PE"
        )

    def test_detect_wasm(self):
        self.assertEqual(
            self.engine._detect_format(WASM_MAGIC + b"\x00" * 4),
            "WASM"
        )

    def test_detect_macho64(self):
        data = struct.pack("<I", 0xFEEDFACF) + b"\x00" * 4
        self.assertEqual(self.engine._detect_format(data), "Mach-O")

    def test_detect_macho32(self):
        data = struct.pack("<I", 0xFEEDFACE) + b"\x00" * 4
        self.assertEqual(self.engine._detect_format(data), "Mach-O")

    def test_detect_macho_fat(self):
        data = struct.pack(">I", 0xCAFEBABE) + b"\x00" * 4
        self.assertEqual(self.engine._detect_format(data), "Mach-O")

    def test_detect_raw_unknown(self):
        self.assertEqual(
            self.engine._detect_format(b"\xDE\xAD\xBE\xEF" * 4),
            "raw"
        )

    def test_detect_empty(self):
        self.assertEqual(self.engine._detect_format(b""), "raw")


# ---------------------------------------------------------------------------
# ELF parser tests
# ---------------------------------------------------------------------------

class TestELFParser(unittest.TestCase):

    def setUp(self):
        self.elf64 = make_minimal_elf64()
        self.elf32 = make_minimal_elf32()

    def test_elf64_format(self):
        ir = ELFParser(self.elf64, "test.elf").parse()
        self.assertEqual(ir["format"], "ELF")

    def test_elf64_arch(self):
        ir = ELFParser(self.elf64, "test.elf").parse()
        self.assertEqual(ir["arch"], "x86_64")

    def test_elf64_bits(self):
        ir = ELFParser(self.elf64, "test.elf").parse()
        self.assertEqual(ir["bits"], 64)

    def test_elf32_arch(self):
        ir = ELFParser(self.elf32, "test.elf").parse()
        self.assertEqual(ir["arch"], "x86")

    def test_elf32_bits(self):
        ir = ELFParser(self.elf32, "test.elf").parse()
        self.assertEqual(ir["bits"], 32)

    def test_ir_has_required_keys(self):
        ir = ELFParser(self.elf64, "test.elf").parse()
        for key in ("file", "format", "arch", "language",
                    "sections", "symbols", "strings",
                    "security", "nodes", "edges", "metadata"):
            self.assertIn(key, ir)

    def test_security_dict_present(self):
        ir = ELFParser(self.elf64, "test.elf").parse()
        for key in ("nx", "pie", "stack_canary"):
            self.assertIn(key, ir["security"])

    def test_stack_canary_detected(self):
        ir = ELFParser(self.elf64, "test.elf").parse()
        self.assertTrue(ir["security"]["stack_canary"])

    def test_pie_et_dyn(self):
        # Patch e_type to ET_DYN (3) = PIE
        data = bytearray(self.elf64)
        struct.pack_into("<H", data, 16, 3)
        ir = ELFParser(bytes(data), "test.elf").parse()
        self.assertTrue(ir["security"]["pie"])

    def test_pie_et_exec_not_pie(self):
        ir = ELFParser(self.elf64, "test.elf").parse()
        self.assertFalse(ir["security"]["pie"])

    def test_metadata_has_section_count(self):
        ir = ELFParser(self.elf64, "test.elf").parse()
        self.assertIn("section_count", ir["metadata"])

    def test_nodes_is_list(self):
        ir = ELFParser(self.elf64, "test.elf").parse()
        self.assertIsInstance(ir["nodes"], list)

    def test_edges_is_list(self):
        ir = ELFParser(self.elf64, "test.elf").parse()
        self.assertIsInstance(ir["edges"], list)

    def test_too_small_returns_error(self):
        ir = ELFParser(b"\x7fELF\x02\x01", "bad.elf").parse()
        self.assertIn("error", ir["metadata"])

    def test_go_language_fingerprint(self):
        data = make_go_binary_stub()
        ir   = ELFParser(data, "go_bin").parse()
        self.assertEqual(ir["language"], "go")

    def test_rust_language_fingerprint(self):
        data = make_rust_binary_stub()
        ir   = ELFParser(data, "rust_bin").parse()
        self.assertEqual(ir["language"], "rust")


# ---------------------------------------------------------------------------
# PE parser tests
# ---------------------------------------------------------------------------

class TestPEParser(unittest.TestCase):

    def setUp(self):
        self.pe_basic    = make_minimal_pe()
        self.pe_secure   = make_pe_with_security()

    def test_pe_format(self):
        ir = PEParser(self.pe_basic, "test.exe").parse()
        self.assertEqual(ir["format"], "PE")

    def test_pe_arch_x64(self):
        ir = PEParser(self.pe_basic, "test.exe").parse()
        self.assertEqual(ir["arch"], "x86_64")

    def test_pe_has_required_keys(self):
        ir = PEParser(self.pe_basic, "test.exe").parse()
        for key in ("file", "format", "arch", "language",
                    "sections", "symbols", "strings",
                    "security", "nodes", "edges", "metadata"):
            self.assertIn(key, ir)

    def test_pe_security_keys(self):
        ir = PEParser(self.pe_basic, "test.exe").parse()
        for key in ("nx", "pie", "stack_canary"):
            self.assertIn(key, ir["security"])

    def test_pe_secure_nx(self):
        ir = PEParser(self.pe_secure, "secure.exe").parse()
        self.assertTrue(ir["security"]["nx"])

    def test_pe_secure_pie(self):
        ir = PEParser(self.pe_secure, "secure.exe").parse()
        self.assertTrue(ir["security"]["pie"])

    def test_pe_too_small(self):
        ir = PEParser(b"MZ\x00", "bad.exe").parse()
        self.assertIn("error", ir["metadata"])

    def test_pe_invalid_signature(self):
        data = bytearray(make_minimal_pe())
        # corrupt PE sig
        data[64:68] = b"XX\x00\x00"
        ir = PEParser(bytes(data), "bad.exe").parse()
        self.assertIn("error", ir["metadata"])


# ---------------------------------------------------------------------------
# Mach-O parser tests
# ---------------------------------------------------------------------------

class TestMachOParser(unittest.TestCase):

    def setUp(self):
        self.macho64 = make_minimal_macho64()

    def test_macho_format(self):
        ir = MachOParser(self.macho64, "test").parse()
        self.assertEqual(ir["format"], "Mach-O")

    def test_macho_arch(self):
        ir = MachOParser(self.macho64, "test").parse()
        self.assertEqual(ir["arch"], "x86_64")

    def test_macho_bits(self):
        ir = MachOParser(self.macho64, "test").parse()
        self.assertEqual(ir["bits"], 64)

    def test_macho_pie_from_flags(self):
        ir = MachOParser(self.macho64, "test").parse()
        self.assertTrue(ir["security"]["pie"])

    def test_macho_has_required_keys(self):
        ir = MachOParser(self.macho64, "test").parse()
        for key in ("file", "format", "arch", "language",
                    "sections", "symbols", "security",
                    "nodes", "edges", "metadata"):
            self.assertIn(key, ir)

    def test_macho_no_pie(self):
        data = bytearray(self.macho64)
        # Clear MH_PIE flag at offset 24 (flags field in Mach-O header)
        struct.pack_into("<I", data, 24, 0)
        ir = MachOParser(bytes(data), "test").parse()
        self.assertFalse(ir["security"]["pie"])

    def test_macho_too_small(self):
        ir = MachOParser(b"\x00\x01", "bad").parse()
        self.assertIn("error", ir["metadata"])


# ---------------------------------------------------------------------------
# WASM parser tests
# ---------------------------------------------------------------------------

class TestWASMParser(unittest.TestCase):

    def setUp(self):
        self.wasm = make_minimal_wasm()

    def test_wasm_format(self):
        ir = WASMParser(self.wasm, "test.wasm").parse()
        self.assertEqual(ir["format"], "WASM")

    def test_wasm_arch(self):
        ir = WASMParser(self.wasm, "test.wasm").parse()
        self.assertEqual(ir["arch"], "wasm32")

    def test_wasm_has_sections(self):
        ir = WASMParser(self.wasm, "test.wasm").parse()
        self.assertIsInstance(ir["sections"], list)
        self.assertGreater(len(ir["sections"]), 0)

    def test_wasm_sandbox_security(self):
        ir = WASMParser(self.wasm, "test.wasm").parse()
        self.assertTrue(ir["security"]["nx"])
        self.assertTrue(ir["security"]["pie"])

    def test_wasm_has_required_keys(self):
        ir = WASMParser(self.wasm, "test.wasm").parse()
        for key in ("file", "format", "arch", "language",
                    "sections", "symbols", "security",
                    "nodes", "edges", "metadata"):
            self.assertIn(key, ir)

    def test_wasm_too_small(self):
        ir = WASMParser(b"\x00asm", "bad.wasm").parse()
        self.assertIn("error", ir["metadata"])

    def test_wasm_with_imports(self):
        # WASM with import section
        header   = b"\x00asm" + struct.pack("<I", 1)
        # Import: module="env", name="system", kind=0 (func), type_idx=0
        mod  = b"\x03env"
        name = b"\x06system"
        kind = b"\x00"
        idx  = b"\x00"
        entry = mod + name + kind + idx
        count = b"\x01"
        body  = count + entry
        sec   = bytes([2, len(body)]) + body
        wasm  = header + sec
        ir    = WASMParser(wasm, "test.wasm").parse()
        self.assertIsInstance(ir["symbols"], list)


# ---------------------------------------------------------------------------
# Raw binary parser tests
# ---------------------------------------------------------------------------

class TestRawBinaryParser(unittest.TestCase):

    def test_raw_format(self):
        ir = RawBinaryParser(make_raw_with_dangerous(),
                             "raw.bin").parse()
        self.assertEqual(ir["format"], "raw")

    def test_raw_detects_dangerous_strings(self):
        ir = RawBinaryParser(make_raw_with_dangerous(),
                             "raw.bin").parse()
        dangerous = [s for s in ir["symbols"]
                     if s.get("dangerous")]
        self.assertGreater(len(dangerous), 0)

    def test_raw_has_required_keys(self):
        ir = RawBinaryParser(b"\x00" * 64, "raw.bin").parse()
        for key in ("file", "format", "arch", "language",
                    "sections", "symbols", "strings",
                    "security", "nodes", "edges", "metadata"):
            self.assertIn(key, ir)

    def test_raw_go_fingerprint(self):
        data = (b"\xDE\xAD\xBE\xEF" * 8 +
                b"runtime.main\x00goroutine\x00")
        ir = RawBinaryParser(data, "raw.bin").parse()
        self.assertEqual(ir["language"], "go")

    def test_raw_rust_fingerprint(self):
        data = (b"\xDE\xAD\xBE\xEF" * 8 +
                b"core::panicking\x00rust_begin_unwind\x00")
        ir = RawBinaryParser(data, "raw.bin").parse()
        self.assertEqual(ir["language"], "rust")


# ---------------------------------------------------------------------------
# Security report builder tests
# ---------------------------------------------------------------------------

class TestSecurityReportBuilder(unittest.TestCase):

    def _make_ir(self, security, symbols=None, sections=None):
        return {
            "format":   "ELF",
            "arch":     "x86_64",
            "security": security,
            "symbols":  symbols or [],
            "sections": sections or [],
        }

    def test_missing_nx_generates_finding(self):
        ir  = self._make_ir({"nx": False, "pie": True,
                              "stack_canary": True})
        f   = SecurityReportBuilder(ir).build_findings()
        cats = [x["category"] for x in f]
        self.assertIn("MISSING_NX", cats)

    def test_missing_pie_generates_finding(self):
        ir  = self._make_ir({"nx": True, "pie": False,
                              "stack_canary": True})
        f   = SecurityReportBuilder(ir).build_findings()
        cats = [x["category"] for x in f]
        self.assertIn("MISSING_PIE", cats)

    def test_missing_canary_generates_finding(self):
        ir  = self._make_ir({"nx": True, "pie": True,
                              "stack_canary": False})
        f   = SecurityReportBuilder(ir).build_findings()
        cats = [x["category"] for x in f]
        self.assertIn("MISSING_STACK_CANARY", cats)

    def test_missing_relro_generates_finding(self):
        ir  = self._make_ir({"nx": True, "pie": True,
                              "stack_canary": True,
                              "relro": "none"})
        f   = SecurityReportBuilder(ir).build_findings()
        cats = [x["category"] for x in f]
        self.assertIn("MISSING_RELRO", cats)

    def test_dangerous_import_generates_finding(self):
        syms = [{"name":      "system",
                 "type":      "import",
                 "dangerous": True,
                 "offset":    100}]
        ir = self._make_ir({"nx": True, "pie": True,
                             "stack_canary": True}, symbols=syms)
        f  = SecurityReportBuilder(ir).build_findings()
        cats = [x["category"] for x in f]
        self.assertIn("DANGEROUS_IMPORT", cats)

    def test_high_entropy_section_generates_finding(self):
        secs = [{"name":    ".packed",
                 "size":    4096,
                 "entropy": 7.9,
                 "flags":   0}]
        ir = self._make_ir({"nx": True, "pie": True,
                             "stack_canary": True},
                           sections=secs)
        f  = SecurityReportBuilder(ir).build_findings()
        cats = [x["category"] for x in f]
        self.assertIn("HIGH_ENTROPY_SECTION", cats)

    def test_fully_hardened_binary_no_findings(self):
        ir = self._make_ir({
            "nx":           True,
            "pie":          True,
            "stack_canary": True,
            "relro":        "full",
            "fortify":      True,
        })
        f = SecurityReportBuilder(ir).build_findings()
        self.assertEqual(len(f), 0)

    def test_finding_has_required_keys(self):
        ir = self._make_ir({"nx": False, "pie": False,
                             "stack_canary": False})
        f  = SecurityReportBuilder(ir).build_findings()
        self.assertGreater(len(f), 0)
        for key in ("id", "category", "description", "severity"):
            self.assertIn(key, f[0])

    def test_finding_ids_are_unique(self):
        ir = self._make_ir({"nx": False, "pie": False,
                             "stack_canary": False})
        f   = SecurityReportBuilder(ir).build_findings()
        ids = [x["id"] for x in f]
        self.assertEqual(len(ids), len(set(ids)))

    def test_wasm_no_pie_finding(self):
        # WASM is always sandboxed -- no PIE finding expected
        ir = self._make_ir({"nx": True, "pie": False,
                             "stack_canary": False})
        ir["format"] = "WASM"
        f    = SecurityReportBuilder(ir).build_findings()
        cats = [x["category"] for x in f]
        self.assertNotIn("MISSING_PIE", cats)


# ---------------------------------------------------------------------------
# BinaryLiftingEngine integration tests
# ---------------------------------------------------------------------------

class TestBinaryLiftingEngine(unittest.TestCase):

    def setUp(self):
        self.engine = BinaryLiftingEngine()

    def test_lift_elf_file(self):
        data = make_minimal_elf64()
        with tempfile.NamedTemporaryFile(suffix=".elf",
                                         delete=False) as f:
            f.write(data); path = f.name
        try:
            ir = self.engine.lift(path)
            self.assertEqual(ir["format"], "ELF")
        finally:
            os.unlink(path)

    def test_lift_pe_file(self):
        data = make_minimal_pe()
        with tempfile.NamedTemporaryFile(suffix=".exe",
                                         delete=False) as f:
            f.write(data); path = f.name
        try:
            ir = self.engine.lift(path)
            self.assertEqual(ir["format"], "PE")
        finally:
            os.unlink(path)

    def test_lift_wasm_file(self):
        data = make_minimal_wasm()
        with tempfile.NamedTemporaryFile(suffix=".wasm",
                                         delete=False) as f:
            f.write(data); path = f.name
        try:
            ir = self.engine.lift(path)
            self.assertEqual(ir["format"], "WASM")
        finally:
            os.unlink(path)

    def test_lift_bytes_elf(self):
        ir = self.engine.lift_bytes(make_minimal_elf64(),
                                    "test.elf")
        self.assertEqual(ir["format"], "ELF")

    def test_lift_bytes_pe(self):
        ir = self.engine.lift_bytes(make_minimal_pe(),
                                    "test.exe")
        self.assertEqual(ir["format"], "PE")

    def test_lift_bytes_wasm(self):
        ir = self.engine.lift_bytes(make_minimal_wasm(),
                                    "test.wasm")
        self.assertEqual(ir["format"], "WASM")

    def test_lift_bytes_raw(self):
        ir = self.engine.lift_bytes(b"\xDE\xAD" * 32,
                                    "raw.bin")
        self.assertEqual(ir["format"], "raw")

    def test_lift_adds_hash(self):
        ir = self.engine.lift_bytes(make_minimal_elf64())
        self.assertIn("hash", ir)
        self.assertEqual(len(ir["hash"]), 64)

    def test_lift_adds_timestamp(self):
        ir = self.engine.lift_bytes(make_minimal_elf64())
        self.assertIn("lifted_at", ir)

    def test_lift_adds_findings(self):
        ir = self.engine.lift_bytes(make_minimal_elf64())
        self.assertIn("findings", ir)
        self.assertIsInstance(ir["findings"], list)

    def test_file_not_found_raises(self):
        with self.assertRaises(FileNotFoundError):
            self.engine.lift("/nonexistent/path/binary.elf")

    def test_export_json(self):
        ir = self.engine.lift_bytes(make_minimal_elf64(),
                                    "test.elf")
        with tempfile.NamedTemporaryFile(suffix=".json",
                                         delete=False) as f:
            path = f.name
        try:
            self.engine.export_json(ir, path)
            import json
            with open(path) as f:
                loaded = json.load(f)
            self.assertEqual(loaded["format"], "ELF")
        finally:
            os.unlink(path)

    def test_lift_macho_bytes(self):
        ir = self.engine.lift_bytes(make_minimal_macho64(),
                                    "test.macho")
        self.assertEqual(ir["format"], "Mach-O")

    def test_finding_count_in_metadata(self):
        ir = self.engine.lift_bytes(make_minimal_elf64())
        self.assertIn("finding_count", ir["metadata"])

    def test_hardened_elf_fewer_findings(self):
        # ELF with canary -- fewer security findings
        data = make_minimal_elf64()  # already has canary
        ir   = self.engine.lift_bytes(data, "hardened.elf")
        canary_findings = [
            f for f in ir["findings"]
            if f["category"] == "MISSING_STACK_CANARY"
        ]
        self.assertEqual(len(canary_findings), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
