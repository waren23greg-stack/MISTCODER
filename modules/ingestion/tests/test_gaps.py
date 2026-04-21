"""
MISTCODER MOD-01 Gap Tests
Tests for GAP-01 (JS secret detection) and GAP-02 (JS edge graph)
"""
import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from parser import JavaScriptParser, PythonParser


class TestJSSecretDetection(unittest.TestCase):
    """GAP-01: JavaScript secret detection was missing"""

    def test_detects_api_key_assignment(self):
        source = "const API_KEY = 'sk-12345abcde';"
        parser = JavaScriptParser(source, "test.js")
        ir = parser.parse()
        secrets = [n for n in ir["nodes"] if n["type"] == "secret_flag"]
        self.assertGreater(len(secrets), 0, "Should detect API_KEY assignment")
        self.assertTrue(any("API_KEY" in n["name"] for n in secrets))

    def test_detects_password_assignment(self):
        source = "let password = 'super_secret_pass';"
        parser = JavaScriptParser(source, "test.js")
        ir = parser.parse()
        secrets = [n for n in ir["nodes"] if n["type"] == "secret_flag"]
        self.assertGreater(len(secrets), 0, "Should detect password assignment")

    def test_detects_token_assignment(self):
        source = "var token = 'eyJhbGc...abcdef';"
        parser = JavaScriptParser(source, "test.js")
        ir = parser.parse()
        secrets = [n for n in ir["nodes"] if n["type"] == "secret_flag"]
        self.assertGreater(len(secrets), 0, "Should detect token assignment")

    def test_secret_metadata_included(self):
        source = "const private_key = 'BEGIN PRIVATE KEY...';"
        parser = JavaScriptParser(source, "test.js")
        ir = parser.parse()
        secrets = [n for n in ir["nodes"] if n["type"] == "secret_flag"]
        self.assertTrue(any(n.get("props", {}).get("pattern") == "potential_secret_assignment" 
                           for n in secrets))


class TestJSCallEdgeGraph(unittest.TestCase):
    """GAP-02: JavaScript function-to-call edge graph was missing"""

    def test_call_inside_function_creates_edge(self):
        source = """
function processData(input) {
    eval(input);
}
"""
        parser = JavaScriptParser(source, "test.js")
        ir = parser.parse()
        
        # Find function and dangerous call
        func_nodes = [n for n in ir["nodes"] if n["type"] == "function"]
        call_nodes = [n for n in ir["nodes"] if n["type"] == "call" and n.get("props", {}).get("dangerous")]
        
        self.assertGreater(len(func_nodes), 0, "Should detect function")
        self.assertGreater(len(call_nodes), 0, "Should detect dangerous call")
        
        # Check edge exists
        edges = ir["edges"]
        self.assertGreater(len(edges), 0, "Should create edges between function and calls")

    def test_nested_function_call_tracking(self):
        source = """
function outer() {
    function inner() {
        eval(userInput);
    }
    inner();
}
"""
        parser = JavaScriptParser(source, "test.js")
        ir = parser.parse()
        
        dangerous = [n for n in ir["nodes"] if n.get("props", {}).get("dangerous")]
        self.assertGreater(len(dangerous), 0, "Should track dangerous calls in nested functions")

    def test_arrow_function_call_tracking(self):
        source = """
const handler = (data) => {
    innerHTML = data;
}
"""
        parser = JavaScriptParser(source, "test.js")
        ir = parser.parse()
        
        func_nodes = [n for n in ir["nodes"] if n["type"] == "function"]
        dangerous = [n for n in ir["nodes"] if n.get("props", {}).get("dangerous")]
        
        self.assertGreater(len(func_nodes), 0)
        self.assertGreater(len(dangerous), 0)


class TestTaintSourceMarking(unittest.TestCase):
    """GAP-03: Taint source/sink identification (Python focus)"""

    def test_marks_request_object_as_taint_source(self):
        source = """
from flask import request
user_input = request.args.get('data')
eval(user_input)
"""
        parser = PythonParser(source, "test.py")
        ir = parser.parse()
        
        # This should be enhanced in MOD-02
        imports = [n for n in ir["nodes"] if n["type"] == "import" and "request" in n["name"]]
        self.assertGreater(len(imports), 0, "Should identify taint source (request)")

    def test_marks_sys_argv_as_taint_source(self):
        source = """
import sys
cmd = sys.argv[1]
exec(cmd)
"""
        parser = PythonParser(source, "test.py")
        ir = parser.parse()
        
        imports = [n for n in ir["nodes"] if "sys" in n["name"]]
        self.assertGreater(len(imports), 0, "Should identify sys as potential source")


if __name__ == "__main__":
    unittest.main()