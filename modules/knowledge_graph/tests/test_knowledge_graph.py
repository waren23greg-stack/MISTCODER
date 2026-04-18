"""
MISTCODER -- MOD-07 Knowledge Graph
Test Suite v0.1.0
"""

import os
import sys
import json
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                "..", "..", "ingestion", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                "..", "..", "analysis", "src"))

from knowledge_graph import (
    KGNode, KGEdge, GraphStore,
    KnowledgeGraphBuilder, KnowledgeGraphEngine,
    GraphQueryEngine, AttackSurfaceScorer,
    NODE_TYPES, EDGE_TYPES, SEVERITY_WEIGHT,
)
from parser import PythonParser
from analysis_engine import AnalysisEngine

VULN_SOURCE = (
    "import os\n"
    "password = 'secret123'\n"
    "api_key = 'sk-abc'\n"
    "def run(cmd):\n"
    "    eval(cmd)\n"
    "    os.system(cmd)\n"
)

def make_pipeline(source=VULN_SOURCE, filepath="test.py"):
    ir     = PythonParser(source, filepath).parse()
    report = AnalysisEngine().analyze(ir)
    return ir, report


# ---------------------------------------------------------------------------
# KGNode tests
# ---------------------------------------------------------------------------

class TestKGNode(unittest.TestCase):

    def test_valid_node_creation(self):
        n = KGNode("n1", "SOFTWARE", "myapp.py")
        self.assertEqual(n.id,   "n1")
        self.assertEqual(n.type, "SOFTWARE")
        self.assertEqual(n.name, "myapp.py")

    def test_invalid_type_raises(self):
        with self.assertRaises(ValueError):
            KGNode("n1", "INVALID_TYPE", "x")

    def test_to_dict_has_required_keys(self):
        n = KGNode("n1", "VULNERABILITY", "eval-call", {"severity": "HIGH"})
        d = n.to_dict()
        for key in ("id", "type", "name", "properties", "created_at"):
            self.assertIn(key, d)

    def test_from_dict_roundtrip(self):
        n  = KGNode("n1", "CVE", "CVE-2024-1234", {"cvss": 9.8})
        d  = n.to_dict()
        n2 = KGNode.from_dict(d)
        self.assertEqual(n2.id,   n.id)
        self.assertEqual(n2.name, n.name)
        self.assertEqual(n2.properties, n.properties)

    def test_properties_stored(self):
        n = KGNode("n1", "ASSET", "db", {"criticality": "HIGH"})
        self.assertEqual(n.properties["criticality"], "HIGH")


# ---------------------------------------------------------------------------
# KGEdge tests
# ---------------------------------------------------------------------------

class TestKGEdge(unittest.TestCase):

    def test_valid_edge_creation(self):
        e = KGEdge("e1", "n1", "n2", "CONTAINS", 0.9)
        self.assertEqual(e.src,    "n1")
        self.assertEqual(e.dst,    "n2")
        self.assertEqual(e.type,   "CONTAINS")
        self.assertEqual(e.weight, 0.9)

    def test_invalid_type_raises(self):
        with self.assertRaises(ValueError):
            KGEdge("e1", "n1", "n2", "INVALID_EDGE")

    def test_to_dict_has_required_keys(self):
        e = KGEdge("e1", "n1", "n2", "CHAINS_TO", 0.8)
        d = e.to_dict()
        for key in ("id", "src", "dst", "type", "weight"):
            self.assertIn(key, d)

    def test_from_dict_roundtrip(self):
        e  = KGEdge("e1", "n1", "n2", "AFFECTS", 0.7)
        d  = e.to_dict()
        e2 = KGEdge.from_dict(d)
        self.assertEqual(e2.src,  e.src)
        self.assertEqual(e2.dst,  e.dst)
        self.assertEqual(e2.type, e.type)


# ---------------------------------------------------------------------------
# GraphStore tests
# ---------------------------------------------------------------------------

class TestGraphStore(unittest.TestCase):

    def setUp(self):
        self.store = GraphStore()
        self.n1 = KGNode("n1", "SOFTWARE",      "app.py")
        self.n2 = KGNode("n2", "VULNERABILITY", "eval-call",
                         {"severity": "CRITICAL"})
        self.n3 = KGNode("n3", "ASSET",         "database")
        for n in [self.n1, self.n2, self.n3]:
            self.store.add_node(n)

    def test_add_and_get_node(self):
        self.assertIsNotNone(self.store.get_node("n1"))
        self.assertEqual(self.store.get_node("n1").name, "app.py")

    def test_find_by_type(self):
        vulns = self.store.find_nodes_by_type("VULNERABILITY")
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].id, "n2")

    def test_find_by_name(self):
        found = self.store.find_nodes_by_name("app.py")
        self.assertEqual(len(found), 1)

    def test_find_by_name_case_insensitive(self):
        found = self.store.find_nodes_by_name("APP.PY")
        self.assertEqual(len(found), 1)

    def test_upsert_creates_once(self):
        self.store.upsert_node("SOFTWARE", "service.js")
        self.store.upsert_node("SOFTWARE", "service.js")
        found = self.store.find_nodes_by_name("service.js")
        self.assertEqual(len(found), 1)

    def test_upsert_updates_properties(self):
        self.store.upsert_node("SOFTWARE", "app.py",
                               {"version": "2.0"})
        n = self.store.find_nodes_by_name("app.py")[0]
        self.assertEqual(n.properties.get("version"), "2.0")

    def test_connect_creates_edge(self):
        edge = self.store.connect("n1", "n2", "CONTAINS", 0.9)
        self.assertIsNotNone(edge)

    def test_connect_deduplicates(self):
        self.store.connect("n1", "n2", "CONTAINS", 0.9)
        self.store.connect("n1", "n2", "CONTAINS", 0.7)
        self.assertEqual(len(self.store._edges), 1)

    def test_connect_missing_node_returns_none(self):
        result = self.store.connect("n1", "NONEXISTENT", "CONTAINS")
        self.assertIsNone(result)

    def test_successors(self):
        self.store.connect("n1", "n2", "CONTAINS")
        succs = self.store.successors("n1")
        self.assertEqual(len(succs), 1)
        self.assertEqual(succs[0].id, "n2")

    def test_predecessors(self):
        self.store.connect("n1", "n2", "CONTAINS")
        preds = self.store.predecessors("n2")
        self.assertEqual(len(preds), 1)
        self.assertEqual(preds[0].id, "n1")

    def test_bfs_traversal(self):
        self.store.connect("n1", "n2", "CONTAINS")
        self.store.connect("n2", "n3", "TARGETS")
        visited = self.store.bfs("n1")
        ids = [n.id for n in visited]
        self.assertIn("n1", ids)
        self.assertIn("n2", ids)
        self.assertIn("n3", ids)

    def test_shortest_path(self):
        self.store.connect("n1", "n2", "CONTAINS")
        self.store.connect("n2", "n3", "TARGETS")
        path = self.store.shortest_path("n1", "n3")
        self.assertIsNotNone(path)
        self.assertEqual(path[0], "n1")
        self.assertEqual(path[-1], "n3")

    def test_shortest_path_no_path(self):
        path = self.store.shortest_path("n1", "n3")
        self.assertIsNone(path)

    def test_all_paths(self):
        self.store.connect("n1", "n2", "CONTAINS")
        self.store.connect("n1", "n3", "CONTAINS")
        self.store.connect("n2", "n3", "CHAINS_TO")
        paths = self.store.all_paths("n1", "n3")
        self.assertGreaterEqual(len(paths), 1)

    def test_remove_node_removes_edges(self):
        self.store.connect("n1", "n2", "CONTAINS")
        self.store.remove_node("n1")
        self.assertIsNone(self.store.get_node("n1"))
        self.assertEqual(len(self.store._edges), 0)

    def test_stats_returns_counts(self):
        stats = self.store.stats()
        self.assertIn("node_count", stats)
        self.assertIn("edge_count", stats)
        self.assertEqual(stats["node_count"], 3)

    def test_save_and_load(self):
        self.store.connect("n1", "n2", "CONTAINS")
        with tempfile.NamedTemporaryFile(suffix=".json",
                                         delete=False) as f:
            path = f.name
        try:
            self.store.save(path)
            store2 = GraphStore()
            store2.load(path)
            self.assertEqual(len(store2._nodes), 3)
            self.assertEqual(len(store2._edges), 1)
        finally:
            os.unlink(path)

    def test_clear(self):
        self.store.clear()
        self.assertEqual(len(self.store._nodes), 0)
        self.assertEqual(len(self.store._edges), 0)


# ---------------------------------------------------------------------------
# AttackSurfaceScorer tests
# ---------------------------------------------------------------------------

class TestAttackSurfaceScorer(unittest.TestCase):

    def setUp(self):
        self.store = GraphStore()
        self.n1 = self.store.upsert_node("SOFTWARE", "app",
                                          {"severity": "NONE"})
        self.n2 = self.store.upsert_node("VULNERABILITY", "eval",
                                          {"severity": "CRITICAL"})
        self.store.connect(self.n1.id, self.n2.id, "CONTAINS", 1.0)
        self.scorer = AttackSurfaceScorer(self.store)

    def test_score_returns_dict(self):
        scores = self.scorer.score()
        self.assertIsInstance(scores, dict)

    def test_all_nodes_scored(self):
        scores = self.scorer.score()
        self.assertIn(self.n1.id, scores)
        self.assertIn(self.n2.id, scores)

    def test_vulnerability_scores_higher_than_software(self):
        scores = self.scorer.score()
        self.assertGreater(scores[self.n2.id], scores[self.n1.id])

    def test_empty_graph_returns_empty(self):
        scores = AttackSurfaceScorer(GraphStore()).score()
        self.assertEqual(scores, {})


# ---------------------------------------------------------------------------
# KnowledgeGraphBuilder integration tests
# ---------------------------------------------------------------------------

class TestKnowledgeGraphBuilder(unittest.TestCase):

    def setUp(self):
        self.ir, self.report = make_pipeline()
        self.store   = GraphStore()
        self.builder = KnowledgeGraphBuilder(self.store)

    def test_ingest_returns_dict(self):
        result = self.builder.ingest_scan(self.ir, self.report)
        self.assertIsInstance(result, dict)

    def test_ingest_creates_software_node(self):
        self.builder.ingest_scan(self.ir, self.report,
                                 target_label="test_app")
        sw = self.store.find_nodes_by_name("test_app")
        self.assertEqual(len(sw), 1)
        self.assertEqual(sw[0].type, "SOFTWARE")

    def test_ingest_creates_vuln_nodes(self):
        self.builder.ingest_scan(self.ir, self.report)
        vulns = self.store.find_nodes_by_type("VULNERABILITY")
        self.assertGreater(len(vulns), 0)

    def test_ingest_creates_contains_edges(self):
        self.builder.ingest_scan(self.ir, self.report,
                                 target_label="app2")
        sw    = self.store.find_nodes_by_name("app2")[0]
        succs = self.store.successors(sw.id, "CONTAINS")
        self.assertGreater(len(succs), 0)

    def test_ingest_stats_in_result(self):
        result = self.builder.ingest_scan(self.ir, self.report)
        self.assertIn("stats",      result)
        self.assertIn("graph_stats", result)

    def test_add_cve_creates_node(self):
        self.builder.add_cve("CVE-2024-9999", "Test CVE",
                             "CRITICAL", 9.8)
        cves = self.store.find_nodes_by_type("CVE")
        self.assertTrue(any(c.name == "CVE-2024-9999" for c in cves))

    def test_add_threat_actor(self):
        self.builder.add_threat_actor("APT-TEST",
                                      capabilities=["RCE"])
        actors = self.store.find_nodes_by_type("ATTACKER")
        self.assertTrue(any(a.name == "APT-TEST" for a in actors))

    def test_multi_scan_deduplication(self):
        self.builder.ingest_scan(self.ir, self.report,
                                 target_label="same_app")
        self.builder.ingest_scan(self.ir, self.report,
                                 target_label="same_app")
        sw = self.store.find_nodes_by_name("same_app")
        self.assertEqual(len(sw), 1)


# ---------------------------------------------------------------------------
# KnowledgeGraphEngine integration tests
# ---------------------------------------------------------------------------

class TestKnowledgeGraphEngine(unittest.TestCase):

    def setUp(self):
        self.ir, self.report = make_pipeline()
        self.engine = KnowledgeGraphEngine()

    def test_ingest_returns_result(self):
        result = self.engine.ingest(self.ir, self.report)
        self.assertIn("stats", result)

    def test_report_has_required_keys(self):
        self.engine.ingest(self.ir, self.report)
        report = self.engine.report()
        for key in ("graph_stats", "top_vulnerabilities",
                    "vulnerability_clusters",
                    "cross_scan_chains", "overall_risk"):
            self.assertIn(key, report)

    def test_top_vulnerabilities_sorted(self):
        self.engine.ingest(self.ir, self.report)
        top = self.engine.report()["top_vulnerabilities"]
        if len(top) >= 2:
            self.assertGreaterEqual(
                top[0]["graph_score"], top[1]["graph_score"]
            )

    def test_stats_returns_counts(self):
        self.engine.ingest(self.ir, self.report)
        stats = self.engine.stats()
        self.assertGreater(stats["node_count"], 0)

    def test_persistence_save_load(self):
        with tempfile.NamedTemporaryFile(suffix=".json",
                                         delete=False) as f:
            path = f.name
        try:
            engine1 = KnowledgeGraphEngine(storage_path=path)
            engine1.ingest(self.ir, self.report,
                           target_label="persist_test")
            engine1.save()
            engine2 = KnowledgeGraphEngine(storage_path=path)
            sw = engine2.store.find_nodes_by_name("persist_test")
            self.assertEqual(len(sw), 1)
        finally:
            os.unlink(path)

    def test_multiple_scans_grow_graph(self):
        ir2, report2 = make_pipeline(
            "secret = 'abc'\ndef f(): exec('x')\n",
            "app2.py"
        )
        self.engine.ingest(self.ir, self.report,
                           target_label="scan1")
        stats1 = self.engine.stats()["node_count"]
        self.engine.ingest(ir2, report2,
                           target_label="scan2")
        stats2 = self.engine.stats()["node_count"]
        self.assertGreater(stats2, stats1)

    def test_cross_scan_chain_detection(self):
        ir2, report2 = make_pipeline(
            "eval(x)\nos.system(y)\n", "app2.py"
        )
        self.engine.ingest(self.ir, self.report,
                           target_label="svc1")
        self.engine.ingest(ir2, report2,
                           target_label="svc2")
        report = self.engine.report()
        self.assertIsInstance(
            report["cross_scan_chains"], list
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
