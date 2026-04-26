"""
MISTCODER MOD-08 Tests — Callgraph Builder and x86-64 Disassembly
"""
import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from callgraph_builder import CallgraphBuilder, DangerousCallAnalyzer
from disasm_x86_64 import x86Disassembler, x86CallExtractor


class TestCallgraphBuilder(unittest.TestCase):
    """Test callgraph construction"""

    def setUp(self):
        self.cg = CallgraphBuilder()

    def test_add_function(self):
        node = self.cg.add_function("FN001", "main", "0x400000", 256)
        self.assertIsNotNone(node)
        self.assertEqual(node.name, "main")

    def test_add_call(self):
        self.cg.add_function("FN001", "main", "0x400000")
        self.cg.add_function("FN002", "foo", "0x400100")
        
        result = self.cg.add_call("FN001", "FN002")
        self.assertTrue(result)

    def test_add_duplicate_call_returns_false(self):
        self.cg.add_function("FN001", "main", "0x400000")
        self.cg.add_function("FN002", "foo", "0x400100")
        
        self.cg.add_call("FN001", "FN002")
        result = self.cg.add_call("FN001", "FN002")
        
        self.assertFalse(result)

    def test_find_entry_points(self):
        self.cg.add_function("FN001", "main", "0x400000")
        self.cg.add_function("FN002", "foo", "0x400100")
        self.cg.add_call("FN001", "FN002")
        
        entries = self.cg.find_entry_points()
        
        self.assertIn("FN001", entries)
        self.assertNotIn("FN002", entries)

    def test_find_leaf_functions(self):
        self.cg.add_function("FN001", "main", "0x400000")
        self.cg.add_function("FN002", "foo", "0x400100")
        self.cg.add_call("FN001", "FN002")
        
        leaves = self.cg.find_leaf_functions()
        
        self.assertIn("FN002", leaves)
        self.assertNotIn("FN001", leaves)

    def test_find_call_chains(self):
        self.cg.add_function("FN001", "main", "0x400000")
        self.cg.add_function("FN002", "process", "0x400100")
        self.cg.add_function("FN003", "validate", "0x400200")
        
        self.cg.add_call("FN001", "FN002")
        self.cg.add_call("FN002", "FN003")
        
        chains = self.cg.find_call_chains("FN001")
        
        self.assertGreater(len(chains), 0)
        self.assertIn("FN003", chains[0])

    def test_find_reachable_functions(self):
        self.cg.add_function("FN001", "main", "0x400000")
        self.cg.add_function("FN002", "foo", "0x400100")
        self.cg.add_function("FN003", "bar", "0x400200")
        
        self.cg.add_call("FN001", "FN002")
        self.cg.add_call("FN002", "FN003")
        
        reachable = self.cg.find_reachable_functions("FN001")
        
        self.assertIn("FN002", reachable)
        self.assertIn("FN003", reachable)

    def test_mark_external(self):
        self.cg.add_function("FN001", "printf", "0x7f0000")
        self.cg.mark_external("FN001")
        
        node = self.cg.nodes["FN001"]
        self.assertTrue(node.is_external)

    def test_detect_recursion(self):
        self.cg.add_function("FN001", "factorial", "0x400000")
        self.cg.add_call("FN001", "FN001")
        
        recursion_map = self.cg.detect_recursion()
        
        self.assertTrue(recursion_map.get("FN001", False))

    def test_get_stats(self):
        self.cg.add_function("FN001", "main", "0x400000")
        self.cg.add_function("FN002", "foo", "0x400100")
        self.cg.add_call("FN001", "FN002")
        
        stats = self.cg.get_stats()
        
        self.assertEqual(stats["total_functions"], 2)
        self.assertEqual(stats["total_calls"], 1)


class TestDangerousCallAnalyzer(unittest.TestCase):
    """Test dangerous call path analysis"""

    def setUp(self):
        self.cg = CallgraphBuilder()
        self.analyzer = DangerousCallAnalyzer(self.cg)

    def test_find_dangerous_paths(self):
        self.cg.add_function("FN001", "main", "0x400000")
        self.cg.add_function("FN002", "process", "0x400100")
        self.cg.add_function("FN003", "system", "0x7f0000")
        
        self.cg.add_call("FN001", "FN002")
        self.cg.add_call("FN002", "FN003")
        self.cg.mark_external("FN003")
        
        dangerous = self.analyzer.find_dangerous_paths("FN001")
        
        self.assertGreater(len(dangerous), 0)
        self.assertIn("FN003", dangerous[0]["chain"])

    def test_get_tainted_functions(self):
        self.cg.add_function("FN001", "main", "0x400000")
        self.cg.add_function("FN002", "wrapper", "0x400100")
        self.cg.add_function("FN003", "eval", "0x7f0000")
        
        self.cg.add_call("FN001", "FN002")
        self.cg.add_call("FN002", "FN003")
        
        tainted = self.analyzer.get_tainted_functions()
        
        self.assertIn("FN001", tainted)
        self.assertIn("FN002", tainted)


class Testx86Disassembler(unittest.TestCase):
    """Test x86-64 disassembly"""

    def test_disassemble_simple_code(self):
        # push rbp; mov rbp, rsp; ret
        code = bytes([0x55, 0x48, 0x89, 0xe5, 0xc3])
        
        disasm = x86Disassembler(code)
        instructions = disasm.disassemble()
        
        self.assertGreater(len(instructions), 0)

    def test_identify_push_instruction(self):
        code = bytes([0x55])  # push rbp
        
        disasm = x86Disassembler(code)
        instructions = disasm.disassemble()
        
        self.assertEqual(instructions[0].mnemonic, "push")

    def test_identify_call_instruction(self):
        code = bytes([0xe8, 0x00, 0x00, 0x00, 0x00])  # call
        
        disasm = x86Disassembler(code)
        instructions = disasm.disassemble()
        
        found_call = any(i.is_call for i in instructions)
        self.assertTrue(found_call)

    def test_identify_return_instruction(self):
        code = bytes([0xc3])  # ret
        
        disasm = x86Disassembler(code)
        instructions = disasm.disassemble()
        
        found_ret = any(i.is_return for i in instructions)
        self.assertTrue(found_ret)

    def test_identify_jump_instruction(self):
        code = bytes([0xeb, 0x05])  # jmp short
        
        disasm = x86Disassembler(code)
        instructions = disasm.disassemble()
        
        found_jmp = any(i.is_jump for i in instructions)
        self.assertTrue(found_jmp)

    def test_find_function_prologue(self):
        # push rbp; mov rbp, rsp
        code = bytes([0x55, 0x48, 0x89, 0xe5])
        
        disasm = x86Disassembler(code)
        prologues = disasm.find_function_prologue()
        
        self.assertGreater(len(prologues), 0)

    def test_find_calls(self):
        # Direct call: e8 + 4 bytes offset
        code = bytes([0xe8, 0x00, 0x00, 0x00, 0x00])
        
        disasm = x86Disassembler(code)
        calls = disasm.find_calls()
        
        self.assertGreater(len(calls), 0)

    def test_get_stats(self):
        code = bytes([0x55, 0xc3])  # push rbp; ret
        
        disasm = x86Disassembler(code)
        disasm.disassemble()
        stats = disasm.get_stats()
        
        self.assertIn("total_instructions", stats)
        self.assertIn("call_instructions", stats)
        self.assertIn("dangerous_instructions", stats)

    def test_identify_dangerous_instruction(self):
        # syscall instruction
        code = bytes([0x0f, 0x05])
        
        disasm = x86Disassembler(code)
        disasm.disassemble()
        dangerous = disasm.find_dangerous_instructions()
        
        # Should find dangerous instruction
        self.assertGreater(len(dangerous), 0)


class TestCallExtractor(unittest.TestCase):
    """Test call target extraction"""

    def test_extract_call_targets(self):
        code = bytes([0xe8, 0x05, 0x00, 0x00, 0x00, 0x90])
        
        disasm = x86Disassembler(code)
        disasm.disassemble()
        extractor = x86CallExtractor(disasm)
        
        targets = extractor.extract_call_targets()
        
        # Should find at least one call
        self.assertGreater(len(targets), 0)

    def test_find_call_chains(self):
        # Multiple calls with returns
        code = bytes([
            0xe8, 0x00, 0x00, 0x00, 0x00,  # call
            0xc3,                            # ret
            0xe8, 0x00, 0x00, 0x00, 0x00,  # call
            0xc3                             # ret
        ])
        
        disasm = x86Disassembler(code)
        disasm.disassemble()
        extractor = x86CallExtractor(disasm)
        
        chains = extractor.find_call_chains()
        
        self.assertGreater(len(chains), 0)


if __name__ == "__main__":
    unittest.main()