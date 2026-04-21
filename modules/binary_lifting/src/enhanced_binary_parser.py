"""
MISTCODER MOD-08 Enhanced — Binary Lifting Engine
Version 0.2.0 — Expanded format support + IR lowering
"""

import struct
import os
from typing import Optional, Dict, List, Tuple, Any
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DANGEROUS_SYMBOLS = {
    # Standard C library - code execution
    "system", "exec", "execl", "execle", "execlp", "execv", "execve", "execvp",
    # Process spawning
    "fork", "vfork", "clone", "posix_spawn",
    # Shell access
    "popen", "system",
    # Memory manipulation
    "mmap", "mprotect", "mremap",
    # Dynamic loading
    "dlopen", "dlsym", "__libc_dlopen_mode",
    # File access
    "open", "fopen", "openat",
    # Network
    "socket", "connect", "bind", "listen",
    # Windows specific
    "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
    "WinExec", "CreateRemoteThread", "VirtualAllocEx",
    # Java/JNI
    "JNI_CreateJavaVM", "CallStaticVoidMethod",
}

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
MACHO_MAGIC = b"\xfe\xed\xfa"  # Universal Mach-O


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def make_node(node_id: str, node_type: str, name: str, address: Optional[str] = None, 
              props: Optional[Dict] = None) -> Dict:
    return {
        "id": node_id,
        "type": node_type,
        "name": name,
        "address": address,
        "props": props or {}
    }

def make_edge(src: str, dst: str, edge_type: str) -> Dict:
    return {
        "src": src,
        "dst": dst,
        "type": edge_type
    }


# ---------------------------------------------------------------------------
# ELF Parser — Enhanced
# ---------------------------------------------------------------------------

class ELFParser:
    """
    ELF (Executable and Linkable Format) parser for Linux/Unix binaries.
    Extracts symbols, functions, and dangerous calls.
    """

    def __init__(self, data: bytes, filepath: str):
        self.data = data
        self.filepath = filepath
        self.nodes = []
        self.edges = []
        self._id = 0

    def _next_id(self, prefix="N"):
        self._id += 1
        return f"{prefix}{self._id:04d}"

    def parse(self) -> Dict:
        """Parse ELF binary and return IR"""
        if not self.data.startswith(ELF_MAGIC):
            return self._error("Not an ELF file")

        try:
            ei_class = self.data[4]  # 1=32-bit, 2=64-bit
            ei_data = self.data[5]   # 1=little-endian, 2=big-endian
            ei_type = struct.unpack("<H" if ei_data == 1 else ">H", self.data[16:18])[0]
            ei_machine = struct.unpack("<H" if ei_data == 1 else ">H", self.data[18:20])[0]

            arch = self._get_arch(ei_machine)
            bits = 32 if ei_class == 1 else 64

            # Extract entry point
            entry_point_offset = 32 if ei_class == 1 else 32
            entry_point = self._read_addr(entry_point_offset, bits, ei_data)

            entry_node_id = self._next_id("FN")
            self.nodes.append(make_node(entry_node_id, "function", "_entry", 
                                       f"0x{entry_point:x}"))

            # Extract symbol table (simplified - reads from common sections)
            self._extract_symbols(bits, ei_data)

            # Build result
            return {
                "file": self.filepath,
                "format": "ELF",
                "arch": arch,
                "bits": bits,
                "language": "machine-code",
                "entry_point": f"0x{entry_point:x}",
                "nodes": self.nodes,
                "edges": self.edges,
                "metadata": {
                    "file_size": len(self.data),
                    "node_count": len(self.nodes),
                    "edge_count": len(self.edges),
                    "dangerous_calls": len([n for n in self.nodes 
                                           if n.get("props", {}).get("dangerous")]),
                    "parser": "ELFParser v0.2.0"
                }
            }

        except Exception as e:
            return self._error(f"ELF parse error: {e}")

    def _get_arch(self, machine: int) -> str:
        """Map ELF e_machine to architecture"""
        archs = {
            0x03: "i386",
            0x3E: "x86-64",
            0xB7: "aarch64",
            0x28: "arm",
            0x08: "mips",
        }
        return archs.get(machine, "unknown")

    def _read_addr(self, offset: int, bits: int, endian: int) -> int:
        """Read address from binary at offset"""
        size = 4 if bits == 32 else 8
        fmt = "<Q" if bits == 64 else "<I"
        if endian == 2:  # big-endian
            fmt = fmt.replace("<", ">")
        try:
            return struct.unpack(fmt, self.data[offset:offset+size])[0]
        except:
            return 0

    def _extract_symbols(self, bits: int, endian: int):
        """Extract symbol table (simplified)"""
        # In a real implementation, this would parse the symbol table section
        # For now, we extract dangerous function references from the binary
        
        for symbol_name in DANGEROUS_SYMBOLS:
            # Simple heuristic: search for null-terminated symbol names
            pattern = symbol_name.encode() + b"\x00"
            offset = 0
            while True:
                offset = self.data.find(pattern, offset)
                if offset == -1:
                    break
                
                node_id = self._next_id("FN")
                self.nodes.append(make_node(
                    node_id, "call", symbol_name,
                    f"0x{offset:x}",
                    {"dangerous": True}
                ))
                offset += len(pattern)

    def _error(self, msg: str) -> Dict:
        return {
            "file": self.filepath,
            "format": "ELF",
            "language": "unknown",
            "error": msg,
            "nodes": [],
            "edges": [],
            "metadata": {"parser": "ELFParser v0.2.0", "error": msg}
        }


# ---------------------------------------------------------------------------
# PE Parser — Enhanced
# ---------------------------------------------------------------------------

class PEParser:
    """
    PE (Portable Executable) parser for Windows binaries.
    Extracts imports, exports, and dangerous API calls.
    """

    def __init__(self, data: bytes, filepath: str):
        self.data = data
        self.filepath = filepath
        self.nodes = []
        self.edges = []
        self._id = 0

    def _next_id(self, prefix="N"):
        self._id += 1
        return f"{prefix}{self._id:04d}"

    def parse(self) -> Dict:
        """Parse PE binary and return IR"""
        if not self.data.startswith(PE_MAGIC):
            return self._error("Not a PE file")

        try:
            # Read PE signature offset
            pe_offset = struct.unpack("<I", self.data[0x3C:0x40])[0]
            
            if pe_offset + 4 > len(self.data):
                return self._error("Invalid PE offset")

            pe_sig = self.data[pe_offset:pe_offset+4]
            if pe_sig != b"PE\x00\x00":
                return self._error("Invalid PE signature")

            # Determine architecture
            machine = struct.unpack("<H", self.data[pe_offset+4:pe_offset+6])[0]
            arch = self._get_arch(machine)

            # Extract imported DLLs and functions
            self._extract_imports(pe_offset)

            return {
                "file": self.filepath,
                "format": "PE",
                "arch": arch,
                "language": "machine-code",
                "nodes": self.nodes,
                "edges": self.edges,
                "metadata": {
                    "file_size": len(self.data),
                    "node_count": len(self.nodes),
                    "edge_count": len(self.edges),
                    "dangerous_imports": len([n for n in self.nodes 
                                             if n.get("props", {}).get("dangerous")]),
                    "parser": "PEParser v0.2.0"
                }
            }

        except Exception as e:
            return self._error(f"PE parse error: {e}")

    def _get_arch(self, machine: int) -> str:
        archs = {
            0x014C: "i386",
            0x8664: "x86-64",
            0xAA64: "aarch64",
        }
        return archs.get(machine, "unknown")

    def _extract_imports(self, pe_offset: int):
        """Extract imported functions from IAT"""
        # Simplified: search for dangerous API names in the binary
        dangerous_apis = [
            "CreateProcessA", "CreateProcessW", "WinExec",
            "ShellExecuteA", "ShellExecuteW", "CreateRemoteThread",
            "VirtualAllocEx", "WriteProcessMemory",
        ]

        for api in dangerous_apis:
            pattern = api.encode() + b"\x00"
            offset = self.data.find(pattern)
            if offset != -1:
                node_id = self._next_id("CA")
                self.nodes.append(make_node(
                    node_id, "call", api,
                    f"0x{offset:x}",
                    {"dangerous": True}
                ))

    def _error(self, msg: str) -> Dict:
        return {
            "file": self.filepath,
            "format": "PE",
            "language": "unknown",
            "error": msg,
            "nodes": [],
            "edges": [],
            "metadata": {"parser": "PEParser v0.2.0", "error": msg}
        }


# ---------------------------------------------------------------------------
# Binary Lifting Engine — Entry Point
# ---------------------------------------------------------------------------

class BinaryLiftingEngine:
    """
    High-level binary analysis engine.
    Automatically detects format and delegates to appropriate parser.
    """

    def __init__(self):
        pass

    def analyze(self, filepath: str) -> Dict:
        """Analyze a binary and return IR"""
        if not os.path.isfile(filepath):
            return {"error": f"File not found: {filepath}"}

        with open(filepath, "rb") as f:
            data = f.read()

        # Detect format
        if data.startswith(ELF_MAGIC):
            parser = ELFParser(data, filepath)
        elif data.startswith(PE_MAGIC):
            parser = PEParser(data, filepath)
        elif data.startswith(MACHO_MAGIC):
            return {"file": filepath, "error": "Mach-O parsing not yet implemented", "nodes": []}
        else:
            return {"file": filepath, "error": "Unknown binary format", "nodes": []}

        return parser.parse()

    def export_json(self, ir: Dict, output_path: str):
        """Export IR to JSON"""
        import json
        with open(output_path, "w") as f:
            json.dump(ir, f, indent=2)
        print(f"[MOD-08] IR exported to {output_path}")


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python enhanced_binary_parser.py <binary_path> [--export output.json]")
        sys.exit(1)

    binary_path = sys.argv[1]
    export_path = sys.argv[3] if len(sys.argv) >= 4 and sys.argv[2] == "--export" else None

    engine = BinaryLiftingEngine()
    ir = engine.analyze(binary_path)

    print(f"\n[MOD-08] Binary Analysis")
    print(f"File: {binary_path}")
    print(f"Format: {ir.get('format', 'unknown')}")
    print(f"Architecture: {ir.get('arch', 'unknown')}")
    print(f"Nodes: {len(ir.get('nodes', []))}")
    print(f"Dangerous: {ir.get('metadata', {}).get('dangerous_calls', 0)}")

    if export_path:
        engine.export_json(ir, export_path)