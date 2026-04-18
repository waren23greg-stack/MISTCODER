"""
MISTCODER -- MOD-08 Binary Lifting Engine v0.1.0

Lifts compiled binary artifacts to a normalized Intermediate
Representation (IR) compatible with the MOD-02 analysis pipeline.

Supported formats:
    ELF     -- Linux/Unix executables and shared libraries
    PE      -- Windows executables and DLLs (.exe, .dll)
    Mach-O  -- macOS/iOS executables and dylibs
    WASM    -- WebAssembly modules (.wasm)
    Raw     -- Unknown/stripped binaries (heuristic fallback)

Capabilities:
    -- Binary format and architecture detection
    -- Section and segment parsing
    -- Symbol table extraction (imports, exports, debug)
    -- String extraction with entropy scoring
    -- Security feature detection:
           NX / DEP, PIE / ASLR, Stack canaries,
           RELRO (ELF), SafeSEH (PE), Fortify Source
    -- Language fingerprinting (C, Go, Rust, C++)
    -- Control flow hint extraction (call targets, jumps)
    -- Normalized IR output (MOD-01 compatible schema)

All parsing is pure Python -- no external binaries required.
Optional: capstone for richer disassembly (graceful fallback).

Output schema:
    {
        "file":       str,
        "format":     str,
        "arch":       str,
        "language":   str,
        "sections":   [ SectionRecord ],
        "symbols":    [ SymbolRecord ],
        "strings":    [ StringRecord ],
        "security":   SecurityProfile,
        "nodes":      [ IRNode ],
        "edges":      [ IREdge ],
        "metadata":   { ... }
    }
"""

import os
import re
import json
import math
import struct
import hashlib
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# ELF magic
ELF_MAGIC = b"\x7fELF"

# PE magic
PE_MAGIC  = b"MZ"

# Mach-O magic values
MACHO_MAGIC_32     = 0xFEEDFACE
MACHO_MAGIC_64     = 0xFEEDFACF
MACHO_MAGIC_FAT    = 0xCAFEBABE
MACHO_CIGAM_32     = 0xCEFAEDFE
MACHO_CIGAM_64     = 0xCFFAEDFE

# WASM magic
WASM_MAGIC = b"\x00asm"

# ELF architecture codes
ELF_ARCH = {
    0x03: "x86",
    0x3E: "x86_64",
    0x28: "arm32",
    0xB7: "arm64",
    0xF3: "riscv",
    0x08: "mips",
    0x15: "ppc",
    0x16: "ppc64",
    0x02: "sparc",
}

# PE machine codes
PE_MACHINE = {
    0x014C: "x86",
    0x8664: "x86_64",
    0x01C0: "arm32",
    0xAA64: "arm64",
    0x0200: "ia64",
}

# Mach-O CPU types
MACHO_CPU = {
    7:       "x86",
    0x01000007: "x86_64",
    12:      "arm32",
    0x0100000C: "arm64",
    18:      "ppc",
}

# Security-relevant string patterns
SECURITY_PATTERNS = {
    "stack_canary":   [b"__stack_chk_fail", b"__stack_chk_guard",
                       b"stack_guard"],
    "fortify":        [b"__printf_chk", b"__sprintf_chk",
                       b"__strcpy_chk", b"__memcpy_chk",
                       b"_chk_fail"],
    "asan":           [b"__asan_init", b"__asan_report",
                       b"AddressSanitizer"],
    "ubsan":          [b"__ubsan_handle", b"UBSan"],
    "tsan":           [b"__tsan_init", b"ThreadSanitizer"],
    "pie":            [],  # detected via ELF type
    "nx":             [],  # detected via segment flags
}

# Language fingerprints -- byte strings in binary
LANG_PATTERNS = {
    "go": [
        b"runtime.main", b"runtime.goexit", b"runtime.panic",
        b"go.buildid", b"GOROOT", b"goroutine",
        b"runtime.morestack", b"go:buildid",
    ],
    "rust": [
        b"core::panicking", b"std::panicking",
        b"rust_begin_unwind", b"__rust_alloc",
        b"rustc_demangle", b"_ZN4core",
        b"_ZN3std", b"rust_eh_personality",
    ],
    "cpp": [
        b"_ZN", b"_ZS", b"std::vector", b"std::string",
        b"__cxa_throw", b"__gxx_personality",
        b"vtable for ", b"typeinfo for ",
    ],
    "swift": [
        b"swift_retain", b"swift_release",
        b"_TF", b"swift_allocObject",
    ],
    "c": [],  # fallback -- detected by absence of above
}

# Dangerous / interesting imported functions
DANGEROUS_IMPORTS = {
    # Memory
    "gets", "strcpy", "strcat", "sprintf", "scanf",
    "vsprintf", "vprintf", "realpath",
    # Execution
    "system", "popen", "execve", "execl", "execvp",
    "ShellExecute", "WinExec", "CreateProcess",
    # Network
    "connect", "recv", "send", "socket",
    # Crypto weakness
    "MD5_Init", "MD5", "SHA1_Init", "RC4",
    "DES_ecb_encrypt",
    # Format string
    "printf", "fprintf", "syslog",
}

# Minimum printable string length
MIN_STRING_LEN = 5

# Entropy threshold for high-entropy sections (possible encryption/packing)
HIGH_ENTROPY_THRESHOLD = 7.0


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / n
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _extract_strings(data: bytes,
                     min_len: int = MIN_STRING_LEN) -> list:
    results = []
    pattern = re.compile(
        rb"[ -~]{" + str(min_len).encode() + rb",}"
    )
    for m in pattern.finditer(data):
        s = m.group().decode("ascii", errors="replace")
        entropy = _shannon_entropy(m.group())
        results.append({
            "value":   s,
            "offset":  m.start(),
            "length":  len(s),
            "entropy": entropy,
        })
    return results


def _read_cstring(data: bytes, offset: int,
                  max_len: int = 256) -> str:
    end = data.find(b"\x00", offset, offset + max_len)
    if end == -1:
        end = offset + max_len
    try:
        return data[offset:end].decode("utf-8", errors="replace")
    except Exception:
        return ""


def _safe_unpack(fmt: str, data: bytes,
                 offset: int = 0) -> Optional[tuple]:
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        return None
    try:
        return struct.unpack_from(fmt, data, offset)
    except struct.error:
        return None


# ---------------------------------------------------------------------------
# IR node / edge helpers
# ---------------------------------------------------------------------------

def _make_node(node_id: str, node_type: str,
               name: str, line=None, props=None) -> dict:
    return {
        "id":    node_id,
        "type":  node_type,
        "name":  name,
        "line":  line,
        "props": props or {},
    }


def _make_edge(src: str, dst: str, edge_type: str) -> dict:
    return {"src": src, "dst": dst, "type": edge_type}


# ---------------------------------------------------------------------------
# ELF parser
# ---------------------------------------------------------------------------

class ELFParser:
    """
    Pure-Python ELF binary parser.
    Handles 32-bit and 64-bit, little and big endian.
    """

    def __init__(self, data: bytes, filepath: str):
        self.data     = data
        self.filepath = filepath
        self.bits     = 32
        self.endian   = "<"
        self.arch     = "unknown"
        self.sections = []
        self.symbols  = []
        self.security = {}
        self._id      = 0

    def _next_id(self, prefix="B"):
        self._id += 1
        return f"{prefix}{self._id:04d}"

    def parse(self) -> dict:
        data = self.data

        # ELF ident
        if len(data) < 16:
            return self._error("File too small for ELF header")

        ei_class = data[4]   # 1=32bit, 2=64bit
        ei_data  = data[5]   # 1=LE, 2=BE

        self.bits   = 64 if ei_class == 2 else 32
        self.endian = "<" if ei_data == 1 else ">"

        e = self.endian

        if self.bits == 64:
            hdr = _safe_unpack(f"{e}HHIQQQIHHHHHH", data, 16)
            if not hdr:
                return self._error("Cannot parse ELF64 header")
            (e_type, e_machine, e_version, e_entry,
             e_phoff, e_shoff, e_flags, e_ehsize,
             e_phentsize, e_phnum, e_shentsize,
             e_shnum, e_shstrndx) = hdr
        else:
            hdr = _safe_unpack(f"{e}HHIIIIIHHHHHH", data, 16)
            if not hdr:
                return self._error("Cannot parse ELF32 header")
            (e_type, e_machine, e_version, e_entry,
             e_phoff, e_shoff, e_flags, e_ehsize,
             e_phentsize, e_phnum, e_shentsize,
             e_shnum, e_shstrndx) = hdr

        self.arch = ELF_ARCH.get(e_machine, f"elf_0x{e_machine:04x}")

        # PIE detection -- ET_DYN (3) with no fixed load address
        is_pie = (e_type == 3)

        # Parse section headers
        sections  = []
        shstrtab  = b""
        if e_shoff and e_shnum and e_shoff < len(data):
            if self.bits == 64:
                sh_fmt = f"{e}IIQQQQIIQQ"
                sh_sz  = struct.calcsize(sh_fmt)
            else:
                sh_fmt = f"{e}IIIIIIIIII"
                sh_sz  = struct.calcsize(sh_fmt)

            # Read shstrtab first
            if e_shstrndx < e_shnum:
                sh_off = e_shoff + e_shstrndx * sh_sz
                sh     = _safe_unpack(sh_fmt, data, sh_off)
                if sh:
                    str_off  = sh[4] if self.bits == 64 else sh[4]
                    str_size = sh[5] if self.bits == 64 else sh[5]
                    shstrtab = data[str_off: str_off + str_size]

            for i in range(min(e_shnum, 128)):
                sh_off = e_shoff + i * sh_sz
                sh     = _safe_unpack(sh_fmt, data, sh_off)
                if not sh:
                    continue
                if self.bits == 64:
                    (sh_name, sh_type, sh_flags, sh_addr,
                     sh_offset, sh_size, sh_link, sh_info,
                     sh_addralign, sh_entsize) = sh
                else:
                    (sh_name, sh_type, sh_flags, sh_addr,
                     sh_offset, sh_size, sh_link, sh_info,
                     sh_addralign, sh_entsize) = sh

                name = _read_cstring(shstrtab, sh_name) \
                       if sh_name < len(shstrtab) else f"sh_{i}"
                sec_data = data[sh_offset: sh_offset + sh_size] \
                           if sh_offset + sh_size <= len(data) else b""
                entropy  = _shannon_entropy(sec_data)
                sections.append({
                    "name":    name,
                    "type":    sh_type,
                    "offset":  sh_offset,
                    "size":    sh_size,
                    "entropy": entropy,
                    "flags":   sh_flags,
                })
        self.sections = sections

        # Security features
        nx    = self._detect_nx_elf(data, e_phoff, e_phnum,
                                    e_phentsize)
        relro = self._detect_relro(data, e_phoff, e_phnum,
                                   e_phentsize)
        self.security = {
            "nx":           nx,
            "pie":          is_pie,
            "relro":        relro,
            "stack_canary": self._search_bytes(
                                data, SECURITY_PATTERNS["stack_canary"]),
            "fortify":      self._search_bytes(
                                data, SECURITY_PATTERNS["fortify"]),
            "asan":         self._search_bytes(
                                data, SECURITY_PATTERNS["asan"]),
        }

        # Symbol extraction
        symbols = self._extract_symbols_from_strings(data)
        self.symbols = symbols

        # Build IR
        nodes, edges = self._build_ir(symbols, sections, data)

        return {
            "file":     self.filepath,
            "format":   "ELF",
            "arch":     self.arch,
            "bits":     self.bits,
            "language": self._fingerprint_language(data),
            "sections": sections,
            "symbols":  symbols,
            "strings":  _extract_strings(data)[:200],
            "security": self.security,
            "nodes":    nodes,
            "edges":    edges,
            "metadata": {
                "entry_point":  hex(e_entry),
                "pie":          is_pie,
                "section_count": len(sections),
                "symbol_count": len(symbols),
                "node_count":   len(nodes),
                "edge_count":   len(edges),
                "parser":       "ELFParser v0.1.0",
            }
        }

    def _detect_nx_elf(self, data, phoff, phnum, phentsize) -> bool:
        if not phoff or not phnum:
            return False
        e = self.endian
        for i in range(min(phnum, 64)):
            off = phoff + i * phentsize
            if self.bits == 64:
                r = _safe_unpack(f"{e}IIQQQQQQ", data, off)
                if r and r[0] == 0x6474E551:   # PT_GNU_STACK
                    return not bool(r[1] & 0x1)  # no exec flag
            else:
                r = _safe_unpack(f"{e}IIIIIIII", data, off)
                if r and r[0] == 0x6474E551:
                    return not bool(r[7] & 0x1)
        return False

    def _detect_relro(self, data, phoff, phnum, phentsize) -> str:
        full = False
        partial = False
        e = self.endian
        for i in range(min(phnum, 64)):
            off = phoff + i * phentsize
            if self.bits == 64:
                r = _safe_unpack(f"{e}IIQQQQQQ", data, off)
                if r and r[0] == 0x6474E552:   # PT_GNU_RELRO
                    partial = True
            else:
                r = _safe_unpack(f"{e}IIIIIIII", data, off)
                if r and r[0] == 0x6474E552:
                    partial = True
        if self._search_bytes(data, [b"__cfi_slowpath",
                                     b"BIND_NOW"]):
            full = True
        return "full" if full else "partial" if partial else "none"

    def _search_bytes(self, data: bytes,
                      patterns: list) -> bool:
        return any(p in data for p in patterns)

    def _extract_symbols_from_strings(self, data: bytes) -> list:
        symbols = []
        strings = _extract_strings(data, min_len=4)
        for s in strings:
            name = s["value"]
            is_import  = any(d in name for d in DANGEROUS_IMPORTS)
            is_export  = name.startswith("_") and len(name) > 3
            sym_type   = "import" if is_import else "export"
            dangerous  = name in DANGEROUS_IMPORTS or \
                         any(d == name for d in DANGEROUS_IMPORTS)
            if is_import or is_export:
                symbols.append({
                    "name":      name,
                    "type":      sym_type,
                    "dangerous": dangerous,
                    "offset":    s["offset"],
                })
        return symbols[:500]

    def _fingerprint_language(self, data: bytes) -> str:
        scores = {lang: 0 for lang in LANG_PATTERNS}
        for lang, patterns in LANG_PATTERNS.items():
            for p in patterns:
                if p in data:
                    scores[lang] += 1
        best = max(scores, key=lambda k: scores[k])
        if scores[best] == 0:
            return "c"
        return best

    def _build_ir(self, symbols, sections, data):
        nodes = []
        edges = []
        section_ids = {}

        for sec in sections:
            nid = self._next_id("SEC")
            section_ids[sec["name"]] = nid
            high_entropy = sec["entropy"] >= HIGH_ENTROPY_THRESHOLD
            props = {
                "size":         sec["size"],
                "entropy":      sec["entropy"],
                "high_entropy": high_entropy,
                "dangerous":    high_entropy and sec["size"] > 1024,
            }
            nodes.append(_make_node(nid, "section",
                                    sec["name"], None, props))

        for sym in symbols:
            nid  = self._next_id("SYM")
            props = {
                "sym_type":  sym["type"],
                "dangerous": sym["dangerous"],
                "offset":    sym["offset"],
            }
            nodes.append(_make_node(nid, sym["type"],
                                    sym["name"], None, props))
            if sym["dangerous"]:
                text_id = section_ids.get(".text") or \
                          section_ids.get(".code")
                if text_id:
                    edges.append(_make_edge(text_id, nid, "calls"))

        return nodes, edges

    def _error(self, msg: str) -> dict:
        return {
            "file":     self.filepath,
            "format":   "ELF",
            "arch":     "unknown",
            "language": "unknown",
            "sections": [],
            "symbols":  [],
            "strings":  [],
            "security": {},
            "nodes":    [],
            "edges":    [],
            "metadata": {"error": msg, "parser": "ELFParser v0.1.0"},
        }


# ---------------------------------------------------------------------------
# PE parser
# ---------------------------------------------------------------------------

class PEParser:
    """
    Pure-Python PE (Portable Executable) parser.
    Handles 32-bit (PE32) and 64-bit (PE32+).
    """

    def __init__(self, data: bytes, filepath: str):
        self.data     = data
        self.filepath = filepath
        self._id      = 0

    def _next_id(self, prefix="B"):
        self._id += 1
        return f"{prefix}{self._id:04d}"

    def parse(self) -> dict:
        data = self.data

        # DOS header -- get PE offset
        if len(data) < 64:
            return self._error("File too small for PE header")

        e_lfanew = _safe_unpack("<I", data, 60)
        if not e_lfanew:
            return self._error("Cannot read e_lfanew")
        pe_offset = e_lfanew[0]

        if pe_offset + 24 > len(data):
            return self._error("PE signature out of range")

        sig = data[pe_offset: pe_offset + 4]
        if sig != b"PE\x00\x00":
            return self._error("Invalid PE signature")

        # COFF header
        coff = _safe_unpack("<HHIIIHH", data, pe_offset + 4)
        if not coff:
            return self._error("Cannot parse COFF header")
        (machine, num_sections, timestamp, sym_table_ptr,
         num_symbols, opt_hdr_size, characteristics) = coff

        arch = PE_MACHINE.get(machine, f"pe_0x{machine:04x}")

        # Optional header
        opt_off   = pe_offset + 24
        magic     = _safe_unpack("<H", data, opt_off)
        is_64bit  = magic and magic[0] == 0x20B  # PE32+
        bits      = 64 if is_64bit else 32

        # DLL characteristics (for security features)
        dll_chars = 0
        if is_64bit and opt_off + 70 <= len(data):
            r = _safe_unpack("<H", data, opt_off + 70)
            if r:
                dll_chars = r[0]
        elif not is_64bit and opt_off + 70 <= len(data):
            r = _safe_unpack("<H", data, opt_off + 70)
            if r:
                dll_chars = r[0]

        security = {
            "nx":           bool(dll_chars & 0x0100),  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            "pie":          bool(dll_chars & 0x0040),  # DYNAMIC_BASE (ASLR)
            "safeseh":      bool(dll_chars & 0x0400),
            "stack_canary": self._search_bytes(
                                data, SECURITY_PATTERNS["stack_canary"]),
            "fortify":      self._search_bytes(
                                data, SECURITY_PATTERNS["fortify"]),
            "asan":         self._search_bytes(
                                data, SECURITY_PATTERNS["asan"]),
        }

        # Section headers
        sec_off  = opt_off + opt_hdr_size
        sections = []
        for i in range(min(num_sections, 96)):
            sh = _safe_unpack("<8sIIIIIIHHI",
                              data, sec_off + i * 40)
            if not sh:
                break
            (name_raw, vsize, vaddr, raw_size, raw_off,
             reloc_ptr, lineno_ptr, num_relocs,
             num_linenos, characteristics) = sh
            name     = name_raw.rstrip(b"\x00").decode(
                           "ascii", errors="replace")
            sec_data = data[raw_off: raw_off + raw_size] \
                       if raw_off + raw_size <= len(data) else b""
            entropy  = _shannon_entropy(sec_data)
            sections.append({
                "name":    name,
                "vaddr":   vaddr,
                "size":    raw_size,
                "entropy": entropy,
                "flags":   characteristics,
            })

        # Symbol extraction from strings
        symbols  = self._extract_imports(data)
        language = self._fingerprint_language(data)

        nodes, edges = self._build_ir(symbols, sections)

        return {
            "file":     self.filepath,
            "format":   "PE",
            "arch":     arch,
            "bits":     bits,
            "language": language,
            "sections": sections,
            "symbols":  symbols,
            "strings":  _extract_strings(data)[:200],
            "security": security,
            "nodes":    nodes,
            "edges":    edges,
            "metadata": {
                "timestamp":     timestamp,
                "section_count": len(sections),
                "symbol_count":  len(symbols),
                "node_count":    len(nodes),
                "edge_count":    len(edges),
                "parser":        "PEParser v0.1.0",
            }
        }

    def _extract_imports(self, data: bytes) -> list:
        symbols = []
        strings = _extract_strings(data, min_len=4)
        for s in strings:
            name      = s["value"]
            dangerous = name in DANGEROUS_IMPORTS
            if dangerous or (name.endswith(".dll") or
                             name.endswith(".DLL")):
                sym_type = "import"
                symbols.append({
                    "name":      name,
                    "type":      sym_type,
                    "dangerous": dangerous,
                    "offset":    s["offset"],
                })
        return symbols[:500]

    def _search_bytes(self, data, patterns) -> bool:
        return any(p in data for p in patterns)

    def _fingerprint_language(self, data: bytes) -> str:
        scores = {lang: 0 for lang in LANG_PATTERNS}
        for lang, patterns in LANG_PATTERNS.items():
            for p in patterns:
                if p in data:
                    scores[lang] += 1
        best = max(scores, key=lambda k: scores[k])
        return best if scores[best] > 0 else "c"

    def _build_ir(self, symbols, sections):
        nodes = []
        edges = []
        sec_ids = {}
        for sec in sections:
            nid = self._next_id("SEC")
            sec_ids[sec["name"]] = nid
            high_entropy = sec["entropy"] >= HIGH_ENTROPY_THRESHOLD
            nodes.append(_make_node(nid, "section", sec["name"],
                                    None, {
                                        "size":    sec["size"],
                                        "entropy": sec["entropy"],
                                        "dangerous": high_entropy,
                                    }))
        for sym in symbols:
            nid = self._next_id("SYM")
            nodes.append(_make_node(nid, sym["type"],
                                    sym["name"], None, {
                                        "dangerous": sym["dangerous"],
                                    }))
            if sym["dangerous"]:
                text = sec_ids.get(".text")
                if text:
                    edges.append(_make_edge(text, nid, "calls"))
        return nodes, edges

    def _error(self, msg):
        return {
            "file":     self.filepath,
            "format":   "PE",
            "arch":     "unknown",
            "language": "unknown",
            "sections": [],
            "symbols":  [],
            "strings":  [],
            "security": {},
            "nodes":    [],
            "edges":    [],
            "metadata": {"error": msg, "parser": "PEParser v0.1.0"},
        }


# ---------------------------------------------------------------------------
# Mach-O parser
# ---------------------------------------------------------------------------

class MachOParser:
    """
    Pure-Python Mach-O parser.
    Handles 32-bit, 64-bit, and Fat (universal) binaries.
    """

    def __init__(self, data: bytes, filepath: str):
        self.data     = data
        self.filepath = filepath
        self._id      = 0

    def _next_id(self, prefix="B"):
        self._id += 1
        return f"{prefix}{self._id:04d}"

    def parse(self) -> dict:
        data = self.data
        if len(data) < 4:
            return self._error("File too small")

        magic = struct.unpack_from("<I", data, 0)[0]
        if magic in (MACHO_MAGIC_FAT,):
            return self._parse_fat(data)

        swap    = magic in (MACHO_CIGAM_32, MACHO_CIGAM_64)
        is_64   = magic in (MACHO_MAGIC_64, MACHO_CIGAM_64)
        endian  = ">" if swap else "<"
        bits    = 64 if is_64 else 32

        return self._parse_single(data, 0, endian, bits)

    def _parse_fat(self, data: bytes) -> dict:
        # Parse first arch in fat binary
        r = _safe_unpack(">II", data, 0)
        if not r or r[1] == 0:
            return self._error("Empty fat binary")
        n_archs = r[1]
        arch_r  = _safe_unpack(">IIIII", data, 8)
        if not arch_r:
            return self._error("Cannot read fat arch")
        cpu_type, cpu_sub, offset, size, align = arch_r
        slice_data = data[offset: offset + size]
        return self._parse_single(slice_data, 0, "<",
                                  64 if cpu_type & 0x01000000 else 32)

    def _parse_single(self, data: bytes, base: int,
                      endian: str, bits: int) -> dict:
        e = endian
        hdr = _safe_unpack(f"{e}IIIIIII", data, base)
        if not hdr:
            return self._error("Cannot parse Mach-O header")
        (magic, cpu_type, cpu_subtype, filetype,
         ncmds, sizeofcmds, flags) = hdr

        arch     = MACHO_CPU.get(cpu_type, f"macho_0x{cpu_type:08x}")
        hdr_size = 32 if bits == 64 else 28

        # Security flags
        pie = bool(flags & 0x00200000)   # MH_PIE
        nx  = not bool(flags & 0x00100000)  # MH_ALLOW_STACK_EXECUTION absent

        security = {
            "nx":           nx,
            "pie":          pie,
            "stack_canary": self._search_bytes(
                                data, SECURITY_PATTERNS["stack_canary"]),
            "fortify":      self._search_bytes(
                                data, SECURITY_PATTERNS["fortify"]),
            "asan":         self._search_bytes(
                                data, SECURITY_PATTERNS["asan"]),
        }

        # Load commands -- extract section names
        sections = []
        symbols  = []
        off      = base + hdr_size
        for _ in range(min(ncmds, 128)):
            if off + 8 > len(data):
                break
            cmd, cmd_size = struct.unpack_from(f"{e}II", data, off)
            if cmd_size < 8:
                break
            # LC_SEGMENT / LC_SEGMENT_64
            if cmd in (0x1, 0x19):
                sections += self._parse_segment(
                    data, off, e, bits == 64)
            # LC_SYMTAB
            elif cmd == 0x2:
                symbols += self._parse_symtab(data, off, e, bits)
            off += cmd_size

        if not symbols:
            symbols = self._extract_symbols_from_strings(data)

        language = self._fingerprint_language(data)
        nodes, edges = self._build_ir(symbols, sections)

        return {
            "file":     self.filepath,
            "format":   "Mach-O",
            "arch":     arch,
            "bits":     bits,
            "language": language,
            "sections": sections,
            "symbols":  symbols,
            "strings":  _extract_strings(data)[:200],
            "security": security,
            "nodes":    nodes,
            "edges":    edges,
            "metadata": {
                "ncmds":         ncmds,
                "section_count": len(sections),
                "symbol_count":  len(symbols),
                "node_count":    len(nodes),
                "edge_count":    len(edges),
                "parser":        "MachOParser v0.1.0",
            }
        }

    def _parse_segment(self, data, off, e, is_64) -> list:
        sections = []
        if is_64:
            seg = _safe_unpack(f"{e}16sQQIIIIII", data, off + 8)
            if not seg:
                return sections
            nsects = seg[6]
            sec_off = off + 8 + struct.calcsize(f"{e}16sQQIIIIII")
            sec_fmt = f"{e}16s16sQQIIIII"
        else:
            seg = _safe_unpack(f"{e}16sIIIIIIII", data, off + 8)
            if not seg:
                return sections
            nsects = seg[6]
            sec_off = off + 8 + struct.calcsize(f"{e}16sIIIIIIII")
            sec_fmt = f"{e}16s16sIIIIII"

        for i in range(min(nsects, 64)):
            s = _safe_unpack(sec_fmt, data, sec_off)
            if not s:
                break
            sec_name = s[0].rstrip(b"\x00").decode(
                           "ascii", errors="replace")
            seg_name = s[1].rstrip(b"\x00").decode(
                           "ascii", errors="replace")
            if is_64:
                addr, size, file_off = s[2], s[3], s[4]
            else:
                addr, size, file_off = s[2], s[3], s[4]

            sec_data = data[file_off: file_off + size] \
                       if file_off + size <= len(data) else b""
            sections.append({
                "name":    f"{seg_name},{sec_name}",
                "size":    size,
                "offset":  file_off,
                "entropy": _shannon_entropy(sec_data),
                "flags":   0,
            })
            sec_off += struct.calcsize(sec_fmt)

        return sections

    def _parse_symtab(self, data, off, e, bits) -> list:
        lc = _safe_unpack(f"{e}IIII", data, off + 8)
        if not lc:
            return []
        sym_off, nsyms, str_off, strsize = lc
        strtab  = data[str_off: str_off + strsize]
        symbols = []
        entry_size = 16 if bits == 64 else 12
        for i in range(min(nsyms, 500)):
            nlist = _safe_unpack(f"{e}IBBHQ" if bits == 64
                                 else f"{e}IBBHI",
                                 data,
                                 sym_off + i * entry_size)
            if not nlist:
                break
            n_strx = nlist[0]
            name   = _read_cstring(strtab, n_strx)
            if name:
                dangerous = any(d in name
                                for d in DANGEROUS_IMPORTS)
                symbols.append({
                    "name":      name,
                    "type":      "import",
                    "dangerous": dangerous,
                    "offset":    sym_off + i * entry_size,
                })
        return symbols

    def _extract_symbols_from_strings(self, data) -> list:
        symbols = []
        for s in _extract_strings(data, 4):
            name = s["value"]
            if any(d in name for d in DANGEROUS_IMPORTS):
                symbols.append({
                    "name":      name,
                    "type":      "import",
                    "dangerous": True,
                    "offset":    s["offset"],
                })
        return symbols[:500]

    def _search_bytes(self, data, patterns) -> bool:
        return any(p in data for p in patterns)

    def _fingerprint_language(self, data) -> str:
        scores = {lang: 0 for lang in LANG_PATTERNS}
        for lang, patterns in LANG_PATTERNS.items():
            for p in patterns:
                if p in data:
                    scores[lang] += 1
        best = max(scores, key=lambda k: scores[k])
        return best if scores[best] > 0 else "c"

    def _build_ir(self, symbols, sections):
        nodes, edges = [], []
        for sec in sections:
            nid = self._next_id("SEC")
            nodes.append(_make_node(nid, "section",
                                    sec["name"], None,
                                    {"size": sec["size"],
                                     "entropy": sec["entropy"]}))
        for sym in symbols:
            nid = self._next_id("SYM")
            nodes.append(_make_node(nid, sym["type"],
                                    sym["name"], None,
                                    {"dangerous": sym["dangerous"]}))
        return nodes, edges

    def _error(self, msg):
        return {
            "file":     self.filepath,
            "format":   "Mach-O",
            "arch":     "unknown",
            "language": "unknown",
            "sections": [], "symbols": [],
            "strings":  [], "security": {},
            "nodes":    [], "edges":    [],
            "metadata": {"error": msg,
                         "parser": "MachOParser v0.1.0"},
        }


# ---------------------------------------------------------------------------
# WASM parser
# ---------------------------------------------------------------------------

class WASMParser:
    """
    Pure-Python WebAssembly module parser.
    """

    SECTION_NAMES = {
        0: "custom", 1: "type",   2: "import",
        3: "function", 4: "table", 5: "memory",
        6: "global",  7: "export", 8: "start",
        9: "element", 10: "code", 11: "data",
        12: "datacount",
    }

    def __init__(self, data: bytes, filepath: str):
        self.data     = data
        self.filepath = filepath
        self._id      = 0

    def _next_id(self, prefix="B"):
        self._id += 1
        return f"{prefix}{self._id:04d}"

    def _read_leb128(self, data: bytes,
                     offset: int) -> tuple:
        result = 0
        shift  = 0
        while offset < len(data):
            byte    = data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            shift  += 7
            if not (byte & 0x80):
                break
        return result, offset

    def parse(self) -> dict:
        data = self.data
        if len(data) < 8:
            return self._error("File too small")

        version = struct.unpack_from("<I", data, 4)[0]
        sections = []
        symbols  = []
        offset   = 8

        while offset < len(data) - 1:
            if offset >= len(data):
                break
            sec_id = data[offset]; offset += 1
            size, offset = self._read_leb128(data, offset)
            if offset + size > len(data):
                break

            sec_name = self.SECTION_NAMES.get(sec_id,
                                              f"unknown_{sec_id}")
            sec_data = data[offset: offset + size]
            entropy  = _shannon_entropy(sec_data)

            sections.append({
                "name":    sec_name,
                "size":    size,
                "offset":  offset,
                "entropy": entropy,
                "flags":   0,
            })

            # Parse imports
            if sec_id == 2:
                symbols += self._parse_imports(sec_data)

            # Parse exports
            if sec_id == 7:
                symbols += self._parse_exports(sec_data)

            offset += size

        nodes, edges = self._build_ir(symbols, sections)

        return {
            "file":     self.filepath,
            "format":   "WASM",
            "arch":     "wasm32",
            "bits":     32,
            "language": "c",  # WASM typically compiled from C/C++/Rust
            "sections": sections,
            "symbols":  symbols,
            "strings":  _extract_strings(data)[:200],
            "security": {
                "nx":           True,  # WASM sandbox
                "pie":          True,
                "stack_canary": False,
                "fortify":      False,
                "asan":         self._search_bytes(
                                    data, SECURITY_PATTERNS["asan"]),
            },
            "nodes":    nodes,
            "edges":    edges,
            "metadata": {
                "wasm_version":  version,
                "section_count": len(sections),
                "symbol_count":  len(symbols),
                "node_count":    len(nodes),
                "edge_count":    len(edges),
                "parser":        "WASMParser v0.1.0",
            }
        }

    def _parse_imports(self, data: bytes) -> list:
        symbols = []
        count, off = self._read_leb128(data, 0)
        for _ in range(min(count, 500)):
            if off >= len(data):
                break
            mod_len, off = self._read_leb128(data, off)
            mod_name = data[off: off + mod_len].decode(
                           "utf-8", errors="replace")
            off += mod_len
            name_len, off = self._read_leb128(data, off)
            name = data[off: off + name_len].decode(
                       "utf-8", errors="replace")
            off += name_len
            if off >= len(data):
                break
            kind = data[off]; off += 1
            idx, off = self._read_leb128(data, off)
            full_name = f"{mod_name}.{name}"
            dangerous = name in DANGEROUS_IMPORTS
            symbols.append({
                "name":      full_name,
                "type":      "import",
                "dangerous": dangerous,
                "offset":    off,
            })
        return symbols

    def _parse_exports(self, data: bytes) -> list:
        symbols = []
        count, off = self._read_leb128(data, 0)
        for _ in range(min(count, 500)):
            if off >= len(data):
                break
            name_len, off = self._read_leb128(data, off)
            name = data[off: off + name_len].decode(
                       "utf-8", errors="replace")
            off += name_len
            if off >= len(data):
                break
            kind = data[off]; off += 1
            idx, off = self._read_leb128(data, off)
            symbols.append({
                "name":      name,
                "type":      "export",
                "dangerous": False,
                "offset":    off,
            })
        return symbols

    def _search_bytes(self, data, patterns) -> bool:
        return any(p in data for p in patterns)

    def _build_ir(self, symbols, sections):
        nodes, edges = [], []
        for sec in sections:
            nid = self._next_id("SEC")
            nodes.append(_make_node(nid, "section",
                                    sec["name"], None,
                                    {"size": sec["size"],
                                     "entropy": sec["entropy"]}))
        for sym in symbols:
            nid = self._next_id("SYM")
            nodes.append(_make_node(nid, sym["type"],
                                    sym["name"], None,
                                    {"dangerous": sym["dangerous"]}))
        return nodes, edges

    def _error(self, msg):
        return {
            "file":     self.filepath,
            "format":   "WASM",
            "arch":     "wasm32",
            "language": "unknown",
            "sections": [], "symbols": [],
            "strings":  [], "security": {},
            "nodes":    [], "edges":    [],
            "metadata": {"error": msg,
                         "parser": "WASMParser v0.1.0"},
        }


# ---------------------------------------------------------------------------
# Raw / fallback parser
# ---------------------------------------------------------------------------

class RawBinaryParser:
    """
    Fallback parser for unknown or stripped binaries.
    Extracts strings, entropy, and heuristic language hints.
    """

    def __init__(self, data: bytes, filepath: str):
        self.data     = data
        self.filepath = filepath

    def parse(self) -> dict:
        data     = self.data
        strings  = _extract_strings(data)
        entropy  = _shannon_entropy(data)
        symbols  = [s for s in strings
                    if any(d in s["value"]
                           for d in DANGEROUS_IMPORTS)]

        lang  = "unknown"
        for l, patterns in LANG_PATTERNS.items():
            if any(p in data for p in patterns):
                lang = l
                break

        nodes = []
        for i, sym in enumerate(symbols[:100]):
            nodes.append(_make_node(f"RAW{i:04d}", "call",
                                    sym["value"], None,
                                    {"dangerous": True}))
        return {
            "file":     self.filepath,
            "format":   "raw",
            "arch":     "unknown",
            "bits":     0,
            "language": lang,
            "sections": [],
            "symbols":  [{"name":      s["value"],
                          "type":      "string",
                          "dangerous": any(d in s["value"]
                                          for d in DANGEROUS_IMPORTS),
                          "offset":    s["offset"]}
                         for s in symbols[:200]],
            "strings":  strings[:200],
            "security": {
                "nx":           False,
                "pie":          False,
                "stack_canary": any(
                    p in data
                    for p in SECURITY_PATTERNS["stack_canary"]),
                "fortify":      any(
                    p in data
                    for p in SECURITY_PATTERNS["fortify"]),
                "asan":         any(
                    p in data
                    for p in SECURITY_PATTERNS["asan"]),
            },
            "nodes":    nodes,
            "edges":    [],
            "metadata": {
                "file_size":    len(data),
                "entropy":      entropy,
                "node_count":   len(nodes),
                "edge_count":   0,
                "parser":       "RawBinaryParser v0.1.0",
            }
        }


# ---------------------------------------------------------------------------
# Security report builder
# ---------------------------------------------------------------------------

class SecurityReportBuilder:
    """
    Converts raw security profile into structured findings
    compatible with MOD-02 output format.
    """

    def __init__(self, ir: dict):
        self.ir = ir

    def build_findings(self) -> list:
        findings = []
        sec      = self.ir.get("security", {})
        fmt      = self.ir.get("format", "unknown")
        arch     = self.ir.get("arch", "unknown")
        fid      = [0]

        def next_fid():
            fid[0] += 1
            return f"BIN-{fid[0]:05d}"

        if not sec.get("nx", True):
            findings.append({
                "id":          next_fid(),
                "category":    "MISSING_NX",
                "description": (
                    f"{fmt}/{arch} binary has no NX/DEP protection. "
                    "Stack and heap regions may be executable, "
                    "enabling shellcode injection."
                ),
                "severity":    "high",
                "line":        None,
            })

        if not sec.get("pie", False) and fmt != "WASM":
            findings.append({
                "id":          next_fid(),
                "category":    "MISSING_PIE",
                "description": (
                    f"{fmt}/{arch} binary is not position-independent. "
                    "Fixed load address defeats ASLR, simplifying "
                    "ROP/ret2libc exploitation."
                ),
                "severity":    "medium",
                "line":        None,
            })

        if not sec.get("stack_canary", False):
            findings.append({
                "id":          next_fid(),
                "category":    "MISSING_STACK_CANARY",
                "description": (
                    f"{fmt}/{arch} binary has no stack canary. "
                    "Stack buffer overflows may go undetected "
                    "at runtime."
                ),
                "severity":    "medium",
                "line":        None,
            })

        if sec.get("relro") == "none":
            findings.append({
                "id":          next_fid(),
                "category":    "MISSING_RELRO",
                "description": (
                    "ELF binary has no RELRO protection. "
                    "GOT/PLT sections are writable, enabling "
                    "GOT overwrite attacks."
                ),
                "severity":    "medium",
                "line":        None,
            })

        # Dangerous imports
        for sym in self.ir.get("symbols", []):
            if sym.get("dangerous"):
                findings.append({
                    "id":          next_fid(),
                    "category":    "DANGEROUS_IMPORT",
                    "description": (
                        f"Binary imports '{sym['name']}' -- "
                        "a known dangerous function. "
                        "Review usage for unsafe patterns."
                    ),
                    "severity":    "high",
                    "line":        None,
                })

        # High entropy sections
        for sec_item in self.ir.get("sections", []):
            if sec_item.get("entropy", 0) >= HIGH_ENTROPY_THRESHOLD:
                findings.append({
                    "id":          next_fid(),
                    "category":    "HIGH_ENTROPY_SECTION",
                    "description": (
                        f"Section '{sec_item['name']}' has entropy "
                        f"{sec_item['entropy']:.2f} -- possible "
                        "packed, encrypted, or obfuscated code."
                    ),
                    "severity":    "medium",
                    "line":        None,
                })

        return findings


# ---------------------------------------------------------------------------
# Binary Lifting Engine -- entry point
# ---------------------------------------------------------------------------

class BinaryLiftingEngine:
    """
    MOD-08 entry point.

    Detects binary format, dispatches to the appropriate parser,
    builds normalized IR, and produces security findings compatible
    with the MOD-02 analysis pipeline.
    """

    def lift(self, filepath: str) -> dict:
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        with open(filepath, "rb") as f:
            data = f.read()

        file_hash = hashlib.sha256(data).hexdigest()
        fmt       = self._detect_format(data)

        parser_map = {
            "ELF":    ELFParser,
            "PE":     PEParser,
            "Mach-O": MachOParser,
            "WASM":   WASMParser,
        }

        Parser = parser_map.get(fmt, RawBinaryParser)
        ir     = Parser(data, filepath).parse()

        # Add findings
        findings = SecurityReportBuilder(ir).build_findings()
        ir["findings"]   = findings
        ir["hash"]       = file_hash
        ir["lifted_at"]  = datetime.now(timezone.utc).isoformat()
        ir["metadata"]["finding_count"] = len(findings)

        return ir

    def lift_bytes(self, data: bytes,
                   label: str = "<bytes>") -> dict:
        file_hash = hashlib.sha256(data).hexdigest()
        fmt       = self._detect_format(data)

        parser_map = {
            "ELF":    ELFParser,
            "PE":     PEParser,
            "Mach-O": MachOParser,
            "WASM":   WASMParser,
        }

        Parser   = parser_map.get(fmt, RawBinaryParser)
        ir       = Parser(data, label).parse()
        findings = SecurityReportBuilder(ir).build_findings()
        ir["findings"]  = findings
        ir["hash"]      = file_hash
        ir["lifted_at"] = datetime.now(timezone.utc).isoformat()
        ir["metadata"]["finding_count"] = len(findings)
        return ir

    def _detect_format(self, data: bytes) -> str:
        if len(data) < 4:
            return "raw"
        if data[:4] == ELF_MAGIC:
            return "ELF"
        if data[:2] == PE_MAGIC:
            return "PE"
        if data[:4] == WASM_MAGIC:
            return "WASM"
        magic32 = struct.unpack_from("<I", data, 0)[0]
        if magic32 in (MACHO_MAGIC_32, MACHO_MAGIC_64,
                       MACHO_MAGIC_FAT, MACHO_CIGAM_32,
                       MACHO_CIGAM_64):
            return "Mach-O"
        return "raw"

    def export_json(self, ir: dict,
                    output_path: str) -> None:
        os.makedirs(os.path.dirname(
                    os.path.abspath(output_path)),
                    exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(ir, f, indent=2)
        print(f"[MOD-08] IR exported to {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python binary_lifting.py <binary_file> "
              "[--export output.json]")
        sys.exit(1)

    target = sys.argv[1]
    export = sys.argv[3] if (len(sys.argv) >= 4 and
                              sys.argv[2] == "--export") else None

    engine = BinaryLiftingEngine()
    ir     = engine.lift(target)
    m      = ir.get("metadata", {})
    sec    = ir.get("security", {})

    print(f"\n[MOD-08] MISTCODER Binary Lifting Engine v0.1.0")
    print(f"[MOD-08] File     : {ir['file']}")
    print(f"[MOD-08] Format   : {ir['format']}")
    print(f"[MOD-08] Arch     : {ir['arch']}")
    print(f"[MOD-08] Language : {ir['language']}")
    print("=" * 60)
    print(f"  Sections  : {m.get('section_count', 0)}")
    print(f"  Symbols   : {m.get('symbol_count', 0)}")
    print(f"  Findings  : {m.get('finding_count', 0)}")
    print(f"  Nodes     : {m.get('node_count', 0)}")
    print("-" * 60)
    print(f"  NX/DEP    : {sec.get('nx', False)}")
    print(f"  PIE/ASLR  : {sec.get('pie', False)}")
    print(f"  Canary    : {sec.get('stack_canary', False)}")
    print(f"  RELRO     : {sec.get('relro', 'n/a')}")
    print(f"  Fortify   : {sec.get('fortify', False)}")
    print(f"  ASan      : {sec.get('asan', False)}")
    print("-" * 60)
    for f in ir.get("findings", [])[:10]:
        print(f"  [{f['severity'].upper():6s}] "
              f"{f['id']}  {f['category']}")
    print("=" * 60)
    print("[MOD-08] Lifting complete.")

    if export:
        engine.export_json(ir, export)
