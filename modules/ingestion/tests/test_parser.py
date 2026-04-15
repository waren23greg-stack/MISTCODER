"""
MISTCODER -- MOD-01 Ingestion Engine
Test Suite v0.1.0

Tests cover:
    -- Python AST parsing (functions, classes, imports, calls, secret flags)
    -- JavaScript structural parsing
    -- Dangerous call detection
    -- Secret assignment flagging
    -- Directory ingestion
    -- Unknown language fallback
    -- IR schema validation
"""

import os
import sys
import json
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..","src"))
from parser import (
    IngestionEngine,
    PythonParser,
    JavaScriptParser,
    make_node,
    make_edge,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_python(source, filepath="test.py"):
    p = PythonParser(source, filepath)
    return p.parse()

def parse_js(source, filepath="test.js"):
    p = JavaScriptParser(source, filepath)
    return p.parse()


# ---------------------------------------------------------------------------
# Node / Edge record tests
# ---------------------------------------------------------------------------

class TestRecordFactories(unittest.TestCase):

    def test_make_node_required_fields(self):
        n = make_node("N0001", "function", "foo", 10)
        self.assertEqual(n["id"],   "N0001")
        self.assertEqual(n["type"], "function")
        self.assertEqual(n["name"], "foo")
        self.assertEqual(n["line"], 10)
        self.assertIsInstance(n["props"], dict)

    def test_make_node_with_props(self):
        n = make_node("N0002", "call", "eval", 5, {"dangerous": True})
        self.assertTrue(n["props"]["dangerous"])

    def test_make_edge_fields(self):
        e = make_edge("N0001", "N0002", "calls")
        self.assertEqual(e["src"],  "N0001")
        self.assertEqual(e["dst"],  "N0002")
        self.assertEqual(e["type"], "calls")


# ---------------------------------------------------------------------------
# Python parser -- structure detection
# ---------------------------------------------------------------------------

class TestPythonParserFunctions(unittest.TestCase):

    def test_detects_function(self):
        source = "def hello(x, y):\n    return x + y\n"
        ir = parse_python(source)
        names = [n["name"] for n in ir["nodes"] if n["type"] == "function"]
        self.assertIn("hello", names)

    def test_detects_async_function(self):
        source = "async def fetch(url):\n    pass\n"
        ir = parse_python(source)
        fns = [n for n in ir["nodes"] if n["type"] == "function"]
        self.assertTrue(any(f["props"].get("async") for f in fns))

    def test_detects_class(self):
        source = "class Scanner:\n    pass\n"
        ir = parse_python(source)
        classes = [n for n in ir["nodes"] if n["type"] == "class"]
        self.assertTrue(any(c["name"] == "Scanner" for c in classes))

    def test_detects_import(self):
        source = "import os\nimport sys\n"
        ir = parse_python(source)
        imports = [n["name"] for n in ir["nodes"] if n["type"] == "import"]
        self.assertIn("os", imports)
        self.assertIn("sys", imports)

    def test_detects_from_import(self):
        source = "from os.path import join\n"
        ir = parse_python(source)
        imports = [n["name"] for n in ir["nodes"] if n["type"] == "import"]
        self.assertTrue(any("join" in i for i in imports))

    def test_function_args_recorded(self):
        source = "def process(input_data, config):\n    pass\n"
        ir = parse_python(source)
        fns = [n for n in ir["nodes"] if n["type"] == "function"]
        self.assertIn("input_data", fns[0]["props"]["args"])
        self.assertIn("config",     fns[0]["props"]["args"])


# ---------------------------------------------------------------------------
# Python parser -- dangerous call detection
# ---------------------------------------------------------------------------

class TestPythonDangerousCalls(unittest.TestCase):

    def test_detects_eval(self):
        source = "eval(user_input)\n"
        ir = parse_python(source)
        dangerous = [n for n in ir["nodes"] if n.get("props", {}).get("dangerous")]
        self.assertGreater(len(dangerous), 0)

    def test_detects_exec(self):
        source = "exec(code)\n"
        ir = parse_python(source)
        dangerous = [n for n in ir["nodes"] if n.get("props", {}).get("dangerous")]
        self.assertGreater(len(dangerous), 0)

    def test_detects_os_system(self):
        source = "import os\nos.system(cmd)\n"
        ir = parse_python(source)
        dangerous = [n for n in ir["nodes"] if n.get("props", {}).get("dangerous")]
        self.assertGreater(len(dangerous), 0)

    def test_metadata_dangerous_count(self):
        source = "eval(x)\nexec(y)\n"
        ir = parse_python(source)
        self.assertGreaterEqual(ir["metadata"]["dangerous_calls"], 2)

    def test_safe_call_not_flagged(self):
        source = "print('hello')\nlen(items)\n"
        ir = parse_python(source)
        dangerous = [n for n in ir["nodes"] if n.get("props", {}).get("dangerous")]
        self.assertEqual(len(dangerous), 0)


# ---------------------------------------------------------------------------
# Python parser -- secret flag detection
# ---------------------------------------------------------------------------

class TestPythonSecretFlags(unittest.TestCase):

    def test_detects_password_assignment(self):
        source = "password = 'hunter2'\n"
        ir = parse_python(source)
        secrets = [n for n in ir["nodes"] if n["type"] == "secret_flag"]
        self.assertGreater(len(secrets), 0)

    def test_detects_api_key(self):
        source = "api_key = os.environ.get('KEY')\n"
        ir = parse_python(source)
        secrets = [n for n in ir["nodes"] if n["type"] == "secret_flag"]
        self.assertGreater(len(secrets), 0)

    def test_detects_token(self):
        source = "auth_token = get_token()\n"
        ir = parse_python(source)
        secrets = [n for n in ir["nodes"] if n["type"] == "secret_flag"]
        self.assertGreater(len(secrets), 0)

    def test_metadata_secret_count(self):
        source = "password = 'x'\nsecret = 'y'\n"
        ir = parse_python(source)
        self.assertGreaterEqual(ir["metadata"]["secret_flags"], 2)

    def test_normal_variable_not_flagged(self):
        source = "username = 'admin'\ncount = 10\n"
        ir = parse_python(source)
        secrets = [n for n in ir["nodes"] if n["type"] == "secret_flag"]
        self.assertEqual(len(secrets), 0)


# ---------------------------------------------------------------------------
# Python parser -- IR schema
# ---------------------------------------------------------------------------

class TestPythonIRSchema(unittest.TestCase):

    def test_ir_has_required_keys(self):
        ir = parse_python("x = 1\n")
        for key in ("file", "language", "nodes", "edges", "metadata"):
            self.assertIn(key, ir)

    def test_language_is_python(self):
        ir = parse_python("x = 1\n")
        self.assertEqual(ir["language"], "python")

    def test_metadata_has_counts(self):
        ir = parse_python("def f():\n    pass\n")
        for key in ("node_count", "edge_count", "dangerous_calls", "secret_flags"):
            self.assertIn(key, ir["metadata"])

    def test_syntax_error_returns_error_key(self):
        ir = parse_python("def broken(\n")
        self.assertIn("error", ir["metadata"])
        self.assertEqual(ir["nodes"], [])

    def test_nodes_is_list(self):
        ir = parse_python("x = 1\n")
        self.assertIsInstance(ir["nodes"], list)

    def test_edges_is_list(self):
        ir = parse_python("x = 1\n")
        self.assertIsInstance(ir["edges"], list)


# ---------------------------------------------------------------------------
# JavaScript parser
# ---------------------------------------------------------------------------

class TestJavaScriptParser(unittest.TestCase):

    def test_detects_function_declaration(self):
        source = "function authenticate(user, pass) {\n  return true;\n}\n"
        ir = parse_js(source)
        names = [n["name"] for n in ir["nodes"] if n["type"] == "function"]
        self.assertIn("authenticate", names)

    def test_detects_arrow_function(self):
        source = "const fetchData = async (url) => {\n  return url;\n}\n"
        ir = parse_js(source)
        names = [n["name"] for n in ir["nodes"] if n["type"] == "function"]
        self.assertIn("fetchData", names)

    def test_detects_class(self):
        source = "class AuthManager {\n  constructor() {}\n}\n"
        ir = parse_js(source)
        classes = [n for n in ir["nodes"] if n["type"] == "class"]
        self.assertTrue(any(c["name"] == "AuthManager" for c in classes))

    def test_detects_require(self):
        source = "const fs = require('fs');\n"
        ir = parse_js(source)
        imports = [n["name"] for n in ir["nodes"] if n["type"] == "import"]
        self.assertIn("fs", imports)

    def test_detects_import_statement(self):
        source = 'import express from "express";\n'
        ir = parse_js(source)
        imports = [n["name"] for n in ir["nodes"] if n["type"] == "import"]
        self.assertIn("express", imports)

    def test_detects_dangerous_eval(self):
        source = "eval(userInput);\n"
        ir = parse_js(source)
        dangerous = [n for n in ir["nodes"] if n.get("props", {}).get("dangerous")]
        self.assertGreater(len(dangerous), 0)

    def test_detects_inner_html(self):
        source = "element.innerHTML = data;\n"
        ir = parse_js(source)
        dangerous = [n for n in ir["nodes"] if n.get("props", {}).get("dangerous")]
        self.assertGreater(len(dangerous), 0)

    def test_ir_schema(self):
        ir = parse_js("var x = 1;\n")
        for key in ("file", "language", "nodes", "edges", "metadata"):
            self.assertIn(key, ir)

    def test_language_is_javascript(self):
        ir = parse_js("var x = 1;\n")
        self.assertEqual(ir["language"], "javascript")


# ---------------------------------------------------------------------------
# Ingestion engine
# ---------------------------------------------------------------------------

class TestIngestionEngine(unittest.TestCase):

    def setUp(self):
        self.engine = IngestionEngine()

    def test_ingest_python_file(self):
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w",
                                         delete=False, encoding="utf-8") as f:
            f.write("def hello():\n    pass\n")
            self.path = f.name
        ir = self.engine.ingest_file(self.path)
        self.assertEqual(ir["language"], "python")
        os.unlink(self.path)

    def test_ingest_js_file(self):
        with tempfile.NamedTemporaryFile(suffix=".js", mode="w",
                                          delete=False, encoding="utf-8") as f:
            f.write("function greet() {}\n")
            self.path = f.name
        ir = self.engine.ingest_file(self.path)
        self.assertEqual(ir["language"], "javascript")
        os.unlink(self.path)

    def test_ingest_unknown_language(self):
        with tempfile.NamedTemporaryFile(suffix=".rb", mode="w",
                                          delete=False, encoding="utf-8") as f:
            f.write("puts 'hello'\n")
            self.path = f.name
        ir = self.engine.ingest_file(self.path)
        self.assertEqual(ir["language"], "unknown")
        os.unlink(self.path)

    def test_ir_has_hash(self):
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w",
                                          delete=False, encoding="utf-8") as f:
            f.write("x = 1\n")
            self.path = f.name
        ir = self.engine.ingest_file(self.path)
        self.assertIn("hash", ir)
        self.assertEqual(len(ir["hash"]), 64)
        os.unlink(self.path)

    def test_ir_has_parsed_at(self):
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w",
                                          delete=False, encoding="utf-8") as f:
            f.write("x = 1\n")
            self.path = f.name
        ir = self.engine.ingest_file(self.path)
        self.assertIn("parsed_at", ir)
        os.unlink(self.path)

    def test_file_not_found_raises(self):
        with self.assertRaises(FileNotFoundError):
            self.engine.ingest_file("/nonexistent/path/file.py")

    def test_ingest_directory(self):
        with tempfile.TemporaryDirectory() as d:
            for name, content in [
                ("a.py", "def foo(): pass\n"),
                ("b.js", "function bar() {}\n"),
                ("c.txt", "plain text\n"),
            ]:
                with open(os.path.join(d, name), "w") as f:
                    f.write(content)
            results = self.engine.ingest_directory(d)
        langs = [r["language"] for r in results if "language" in r]
        self.assertIn("python",     langs)
        self.assertIn("javascript", langs)
        self.assertEqual(len(results), 2)

    def test_export_json(self):
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w",
                                          delete=False, encoding="utf-8") as f:
            f.write("x = 1\n")
            src = f.name
        with tempfile.NamedTemporaryFile(suffix=".json",
                                          delete=False) as out:
            out_path = out.name
        ir = self.engine.ingest_file(src)
        self.engine.export_json(ir, out_path)
        with open(out_path, "r") as f:
            loaded = json.load(f)
        self.assertEqual(loaded["language"], "python")
        os.unlink(src)
        os.unlink(out_path)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
