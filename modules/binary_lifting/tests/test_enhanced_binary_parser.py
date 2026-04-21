"""
MISTCODER MOD-08 Tests — Binary Lifting and Analysis
"""
import unittest
import struct
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from enhanced_binary_parser import ELFParser, PEParser, BinaryLiftingEngine


class TestELFParser(unittest.TestCase):
    """Tests for ELF binary parser"""

    def create_minimal_elf(self) -> bytes:
        """Create a minimal valid ELF header"""
        elf = bytearray(52)
        elf[0:4] = b"\x7fELF"      # ELF magic
        elf[4] = 2                  # 64-bit
        elf[5] = 1                  # Little-endian
        elf[6] = 1                  # ELF version
        elf[7] = 0                  # UNIX System V ABI
        elf[16:18] = struct.pack("<H", 2)    # ET_EXEC
        elf[18:20] = struct.pack("<H", 0x3E) # x86-64
        elf[32:40] = struct.pack("<Q", 0x400000)  # Entry point
        return bytes(elf)

    def test_elf_magic_detection(self):
        elf = self.create_minimal_elf()
        parser = ELFParser(elf, "test.elf")
        result = parser.parse()
        self.assertEqual(result["format"], "ELF")

    def test_elf_architecture_detection(self):
        elf = self.create_minimal_elf()
        parser = ELFParser(elf, "test.elf")
        result = parser.parse()
        self.assertEqual(result["arch"], "x86-64")

    def test_elf_entry_point_extraction(self):
        elf = self.create_minimal_elf()
        parser = ELFParser(elf, "test.elf")
        result = parser.parse()
        self.assertIn("entry_point", result)
        self.assertEqual(result["entry_point"], "0x400000")

    def test_elf_invalid_file(self):
        bad_elf = b"NOT_ELF_MAGIC_DATA"
        parser = ELFParser(bad_elf, "test.bin")
        result = parser.parse()
        self.assertIn("error", result)


class TestPEParser(unittest.TestCase):
    """Tests for PE binary parser"""

    def create_minimal_pe(self) -> bytes:
        """Create a minimal valid PE header"""
        pe = bytearray(256)
        pe[0:2] = b"MZ"
        pe[0x3C:0x40] = struct.pack("<I", 0x40)  # PE offset at 0x40
        pe[0x40:0x44] = b"PE\x00\x00"
        pe[0x44:0x46] = struct.pack("<H", 0x8664)  # x86-64
        return bytes(pe)

    def test_pe_magic_detection(self):
        pe = self.create_minimal_pe()
        parser = PEParser(pe, "test.exe")
        result = parser.parse()
        self.assertEqual(result["format"], "PE")

    def test_pe_architecture_detection(self):
        pe = self.create_minimal_pe()
        parser = PEParser(pe, "test.exe")
        result = parser.parse()
        self.assertEqual(result["arch"], "x86-64")

    def test_pe_invalid_file(self):
        bad_pe = b"MZ_INVALID_DATA"
        parser = PEParser(bad_pe, "test.exe")
        result = parser.parse()
        self.assertIn("error", result)


class TestBinaryLiftingEngine(unittest.TestCase):
    """Tests for the binary lifting engine"""

    def test_engine_initialization(self):
        engine = BinaryLiftingEngine()
        self.assertIsNotNone(engine)

    def test_missing_file(self):
        engine = BinaryLiftingEngine()
        result = engine.analyze("/nonexistent/file.bin")
        self.assertIn("error", result)

    def test_elf_format_detection(self):
        elf_data = bytearray(52)
        elf_data[0:4] = b"\x7fELF"
        elf_data[4] = 2
        elf_data[5] = 1
        
        # Write to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".elf") as f:
            f.write(bytes(elf_data))
            temp_path = f.name
        
        try:
            engine = BinaryLiftingEngine()
            result = engine.analyze(temp_path)
            self.assertEqual(result["format"], "ELF")
        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    unittest.main()