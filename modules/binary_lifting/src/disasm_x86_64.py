"""
MISTCODER MOD-08 — x86-64 Disassembly Patterns
Version 0.1.0 — Pattern recognition without external dependencies
"""

from typing import List, Dict, Optional, Tuple, Any
import struct


class x86Instruction:
    """Represents a single x86-64 instruction"""

    def __init__(self, address: int, opcode: bytes, mnemonic: str, operands: str = ""):
        self.address = address
        self.opcode = opcode
        self.mnemonic = mnemonic
        self.operands = operands
        self.is_call = mnemonic in ["call", "callq"]
        self.is_jump = mnemonic in ["jmp", "jmpq", "je", "jne", "jz", "jnz", "ja", "jb", "jl", "jg"]
        self.is_return = mnemonic in ["ret", "retq"]
        self.is_dangerous = False

    def to_dict(self) -> Dict:
        return {
            "address": hex(self.address),
            "opcode": self.opcode.hex(),
            "mnemonic": self.mnemonic,
            "operands": self.operands,
            "is_call": self.is_call,
            "is_jump": self.is_jump,
            "is_return": self.is_return,
            "is_dangerous": self.is_dangerous
        }


class x86Disassembler:
    """
    Lightweight x86-64 disassembler using pattern matching.
    No external dependencies required.
    """

    # x86-64 opcode patterns (simplified)
    OPCODES = {
        b"\x48\x89": ("mov", "qword operations"),
        b"\x48\x8b": ("mov", "qword load"),
        b"\x48\x83\xec": ("sub", "rsp (stack adjustment)"),
        b"\x48\x83\xc4": ("add", "rsp (stack cleanup)"),
        b"\xff\x15": ("call", "[rip+offset] (indirect call)"),
        b"\xff\x25": ("jmp", "[rip+offset] (indirect jump)"),
        b"\xe8": ("call", "near (relative)"),
        b"\xe9": ("jmp", "near (relative)"),
        b"\xeb": ("jmp", "short"),
        b"\x74": ("je", "short (equal)"),
        b"\x75": ("jne", "short (not equal)"),
        b"\x7e": ("jle", "short (<=)"),
        b"\x7d": ("jg", "short (>)"),
        b"\xc3": ("ret", ""),
        b"\x90": ("nop", ""),
        b"\x55": ("push", "rbp"),
        b"\x5d": ("pop", "rbp"),
        b"\x50": ("push", "rax"),
        b"\x58": ("pop", "rax"),
        b"\xb8": ("mov", "rax, immediate"),
        b"\xbf": ("mov", "edi, immediate"),
        b"\x0f\x05": ("syscall", ""),
        b"\xcd": ("int", ""),
        b"\xc9": ("leave", ""),
    }

    # Dangerous patterns (code injection indicators)
    DANGEROUS_PATTERNS = {
        b"\xff\x15": "indirect_call",           # call [rip+offset]
        b"\xff\x25": "indirect_jmp",            # jmp [rip+offset]
        b"\x0f\x05": "syscall",                 # Direct syscall
        b"\xcd": "software_interrupt",          # int N
    }

    def __init__(self, binary_data: bytes, base_address: int = 0x400000):
        self.binary = binary_data
        self.base_address = base_address
        self.instructions: List[x86Instruction] = []
        self.dangerous_instructions: List[x86Instruction] = []

    def disassemble(self, start_offset: int = 0, max_instructions: int = 1000) -> List[x86Instruction]:
        """
        Disassemble binary data using pattern matching.
        """
        self.instructions = []
        offset = start_offset
        instr_count = 0

        while offset < len(self.binary) and instr_count < max_instructions:
            instr = self._decode_instruction(offset)
            if instr:
                self.instructions.append(instr)
                offset += len(instr.opcode)
                instr_count += 1
            else:
                offset += 1

        return self.instructions

    def _decode_instruction(self, offset: int) -> Optional[x86Instruction]:
        """Decode a single instruction at offset"""
        if offset >= len(self.binary):
            return None

        # Try multi-byte opcodes first
        for pattern_len in [3, 2, 1]:
            if offset + pattern_len > len(self.binary):
                continue

            pattern = self.binary[offset:offset + pattern_len]

            # Check dangerous patterns
            mnemonic = None
            operands = ""
            is_dangerous = False

            for dangerous_pattern, pattern_name in self.DANGEROUS_PATTERNS.items():
                if pattern.startswith(dangerous_pattern):
                    is_dangerous = True
                    break

            # Check normal patterns
            for opcode_pattern, (mnemonic_name, op_desc) in self.OPCODES.items():
                if pattern.startswith(opcode_pattern):
                    mnemonic = mnemonic_name
                    operands = op_desc
                    break

            if mnemonic:
                instr = x86Instruction(
                    self.base_address + offset,
                    pattern,
                    mnemonic,
                    operands
                )
                instr.is_dangerous = is_dangerous
                if is_dangerous:
                    self.dangerous_instructions.append(instr)
                return instr

        return None

    def find_function_prologue(self, offset: int = 0) -> List[int]:
        """
        Find function prologues (push rbp; mov rsp, rbp pattern).
        """
        prologues = []

        for i in range(offset, len(self.binary) - 2):
            # Look for 0x55 (push rbp)
            if self.binary[i] == 0x55:
                # Check if followed by mov rsp, rbp pattern
                if i + 3 < len(self.binary):
                    if self.binary[i + 1:i + 3] == b"\x48\x89":
                        prologues.append(i)

        return prologues

    def find_calls(self) -> List[int]:
        """Find all call instructions"""
        call_addresses = []

        for i in range(len(self.binary) - 1):
            # Direct call: 0xE8
            if self.binary[i] == 0xe8:
                call_addresses.append(self.base_address + i)
            # Indirect call: 0xFF 0x15
            elif self.binary[i:i + 2] == b"\xff\x15":
                call_addresses.append(self.base_address + i)

        return call_addresses

    def find_dangerous_instructions(self) -> List[x86Instruction]:
        """Return all dangerous instructions found"""
        return self.dangerous_instructions

    def get_stats(self) -> Dict[str, Any]:
        """Get disassembly statistics"""
        calls = sum(1 for i in self.instructions if i.is_call)
        jumps = sum(1 for i in self.instructions if i.is_jump)
        returns = sum(1 for i in self.instructions if i.is_return)

        return {
            "total_instructions": len(self.instructions),
            "call_instructions": calls,
            "jump_instructions": jumps,
            "return_instructions": returns,
            "dangerous_instructions": len(self.dangerous_instructions),
            "coverage_percent": round(100.0 * sum(len(i.opcode) for i in self.instructions) / len(self.binary), 2)
        }


class x86CallExtractor:
    """
    Extract call relationships from disassembled x86-64 code.
    """

    def __init__(self, disassembler: x86Disassembler):
        self.disassembler = disassembler

    def extract_call_targets(self) -> Dict[int, List[int]]:
        """
        Extract targets of call instructions.
        Maps call address -> list of possible targets.
        """
        call_targets = {}

        for instr in self.disassembler.instructions:
            if instr.is_call and len(instr.opcode) > 0:
                # For direct calls (0xE8), compute target
                if instr.opcode[0] == 0xe8 and len(instr.opcode) >= 5:
                    try:
                        # 4-byte relative offset follows opcode
                        offset_bytes = instr.opcode[1:5]
                        offset = struct.unpack("<i", offset_bytes)[0]
                        target = instr.address + 5 + offset
                        call_targets[instr.address] = [target]
                    except:
                        # If unpacking fails, record as unknown target
                        call_targets[instr.address] = []
                # For indirect calls, target is unknown
                elif len(instr.opcode) >= 2 and instr.opcode[:2] == b"\xff\x15":
                    call_targets[instr.address] = []  # Dynamic target
                else:
                    # Other call types
                    call_targets[instr.address] = []

        return call_targets
    def find_call_chains(self, max_depth: int = 5) -> List[List[int]]:
        """
        Find call chains (sequences of calls).
        """
        chains = []
        current_chain = []
        depth = 0

        for instr in self.disassembler.instructions:
            if instr.is_call:
                current_chain.append(instr.address)
                depth += 1

            if instr.is_return or depth >= max_depth:
                if current_chain:
                    chains.append(current_chain)
                current_chain = []
                depth = 0

        return chains


if __name__ == "__main__":
    print("[MOD-08] x86-64 Disassembly Example\n")

    # Create sample x86-64 code (real binary snippet)
    # This is a real x86-64 prologue: push rbp; mov rbp, rsp
    sample_code = bytes([
        0x55,                          # push rbp
        0x48, 0x89, 0xe5,             # mov rbp, rsp
        0x48, 0x83, 0xec, 0x10,       # sub rsp, 0x10
        0xbf, 0x00, 0x00, 0x00, 0x00, # mov edi, 0
        0xe8, 0x00, 0x00, 0x00, 0x00, # call 0x0
        0x90,                          # nop
        0xc3                           # ret
    ])

    disasm = x86Disassembler(sample_code)
    instructions = disasm.disassemble()

    print("Disassembled instructions:")
    for instr in instructions:
        print(f"  {hex(instr.address)}: {instr.mnemonic} {instr.operands}")

    print(f"\nStats: {disasm.get_stats()}")
    print(f"Dangerous instructions: {len(disasm.find_dangerous_instructions())}")

    # Extract calls
    extractor = x86CallExtractor(disasm)
    call_targets = extractor.extract_call_targets()
    print(f"Calls found: {len(call_targets)}")