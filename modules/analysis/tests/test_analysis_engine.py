"""
MISTCODER -- MOD-02 Static Analysis Engine
Test Suite v0.1.0
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                "..", "..", "ingestion", "src"))

from analysis_engine import (
    AnalysisEngine,
    IRGraph,
    TaintAnalyzer,
    CFGBuilder,
    FindingGenerator,
    make_taint_record,
    make_finding,
)
from parser import PythonParser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_ir(source, filepath="test.py"):
    return PythonParser(source, filepath).parse()

def get_report(source, filepath="test.py"):
    ir     = get_ir(source, filepath)
    engine = AnalysisEngine()
    return engine.analyze(ir)


# ---------------------------------------------------------------------------
# IRGraph tests
# ---------------------------------------------------------------------------

class TestIRGraph(unittest.TestCase):

    def setUp(self):
        self.nodes = [
            {"id": "N1", "type": "function", "name": "foo",  "line": 1, "props": {}},
            {"id": "N2", "type": "call",     "name": "eval", "line": 2, "props": {"dangerous": True}},
            {"id": "N3", "type": "call",     "name": "print","line": 3, "props": {}},
        ]
        self.edges = [
            {"src": "N1", "dst": "N2", "type": "calls"},
            {"src": "N1", "dst": "N3", "type": "calls"},
        ]
        self.graph = IRGraph(self.nodes, self.edges)

    def test_nodes_indexed_by_id(self):
        self.assertIn("N1", self.graph.nodes)
        self.assertIn("N2", self.graph.nodes)

    def test_successors(self):
        self.assertIn("N2", self.graph.successors("N1"))
        self.assertIn("N3", self.graph.successors("N1"))

    def test_predecessors(self):
        self.assertIn("N1", self.graph.predecessors("N2"))

    def test_bfs_forward_reaches_all(self):
        visited = self.graph.bfs_forward("N1")
        self.assertIn("N2", visited)
        self.assertIn("N3", visited)

    def test_all_paths_direct(self):
        paths = self.graph.all_paths("N1", "N2")
        self.assertTrue(any("N2" in p for p in paths))

    def test_empty_graph(self):
        g = IRGraph([], [])
        self.assertEqual(g.bfs_forward("X"), ["X"])


# ---------------------------------------------------------------------------
# Analysis engine -- schema
# ---------------------------------------------------------------------------

class TestAnalysisEngineSchema(unittest.TestCase):

    def test_report_has_required_keys(self):
        report = get_report("x = 1\n")
        for key in ("file", "language", "taint_flows",
                    "cfg", "findings", "metadata"):
            self.assertIn(key, report)

    def test_metadata_has_counts(self):
        report = get_report("x = 1\n")
        for key in ("taint_flow_count", "cfg_function_count",
                    "finding_count", "severity_summary"):
            self.assertIn(key, report["metadata"])

    def test_severity_summary_keys(self):
        report = get_report("x = 1\n")
        for key in ("critical", "high", "medium"):
            self.assertIn(key, report["metadata"]["severity_summary"])

    def test_language_preserved(self):
        report = get_report("x = 1\n")
        self.assertEqual(report["language"], "python")

    def test_taint_flows_is_list(self):
        report = get_report("x = 1\n")
        self.assertIsInstance(report["taint_flows"], list)

    def test_findings_is_list(self):
        report = get_report("x = 1\n")
        self.assertIsInstance(report["findings"], list)

    def test_cfg_is_dict(self):
        report = get_report("x = 1\n")
        self.assertIsInstance(report["cfg"], dict)


# ---------------------------------------------------------------------------
# Finding generation
# ---------------------------------------------------------------------------

class TestFindingGeneration(unittest.TestCase):

    def test_dangerous_call_produces_finding(self):
        report = get_report("eval(user_input)\n")
        cats   = [f["category"] for f in report["findings"]]
        self.assertIn("DANGEROUS_CALL", cats)

    def test_secret_flag_produces_finding(self):
        report = get_report("password = 'abc'\n")
        cats   = [f["category"] for f in report["findings"]]
        self.assertIn("SECRET_EXPOSURE", cats)

    def test_finding_has_required_keys(self):
        report = get_report("eval(x)\n")
        if report["findings"]:
            f = report["findings"][0]
            for key in ("id", "category", "description", "severity"):
                self.assertIn(key, f)

    def test_finding_id_format(self):
        report = get_report("eval(x)\n")
        if report["findings"]:
            self.assertTrue(report["findings"][0]["id"].startswith("MIST-"))

    def test_clean_code_no_findings(self):
        source = "def add(a, b):\n    return a + b\n"
        report = get_report(source)
        self.assertEqual(len(report["findings"]), 0)

    def test_severity_count_matches_findings(self):
        report  = get_report("eval(x)\nexec(y)\n")
        summary = report["metadata"]["severity_summary"]
        total   = sum(summary.values())
        self.assertGreaterEqual(len(report["findings"]), total)


# ---------------------------------------------------------------------------
# CFG construction
# ---------------------------------------------------------------------------

class TestCFGBuilder(unittest.TestCase):

    def test_cfg_has_function_entry(self):
        report = get_report("def foo():\n    pass\n")
        self.assertIn("foo", report["cfg"])

    def test_cfg_entry_node(self):
        report = get_report("def bar():\n    pass\n")
        self.assertIn("entry", report["cfg"]["bar"])

    def test_cfg_node_count(self):
        report = get_report("def baz():\n    eval(x)\n")
        self.assertGreaterEqual(report["cfg"]["baz"]["node_count"], 1)

    def test_multiple_functions_in_cfg(self):
        source = "def alpha():\n    pass\ndef beta():\n    pass\n"
        report = get_report(source)
        self.assertIn("alpha", report["cfg"])
        self.assertIn("beta",  report["cfg"])

    def test_no_functions_empty_cfg(self):
        report = get_report("x = 1\ny = 2\n")
        self.assertEqual(len(report["cfg"]), 0)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
