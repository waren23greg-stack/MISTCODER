"""
MISTCODER MOD-07 Tests — Query Builder, Attack Path Finder, TKG Builder
"""
import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cypher_builder import CypherBuilder, AttackPathQueryBuilder, GraphStatisticsBuilder
from attack_path_finder import AttackPath, PathScorer, AttackPathFinder, AdversaryModeler
from threat_kg_builder import ThreatKGBuilder, ThreatModelingPipeline
from neo4j_backend import InMemoryBackend


class TestCypherBuilder(unittest.TestCase):
    """Test Cypher query builder"""

    def test_simple_match_return(self):
        builder = CypherBuilder()
        query = builder.match("(n:Asset)").return_("n").build()
        
        self.assertIn("MATCH (n:Asset)", query["query"])
        self.assertIn("RETURN n", query["query"])

    def test_where_clause_with_parameter(self):
        builder = CypherBuilder()
        query = builder.match("(n:Asset)").where("n.sensitivity", "=", "CRITICAL").return_("n").build()
        
        self.assertIn("WHERE", query["query"])
        self.assertGreater(len(query["params"]), 0)

    def test_multiple_conditions(self):
        builder = CypherBuilder()
        query = (builder
                 .match("(n:Weakness)")
                 .where("n.cvss_score", ">", 8.0)
                 .and_where("n.type", "=", "ConfirmedVuln")
                 .return_("n")
                 .build())
        
        self.assertIn("WHERE", query["query"])
        self.assertIn("AND", query["query"])

    def test_order_limit(self):
        builder = CypherBuilder()
        query = (builder
                 .match("(n:Asset)")
                 .return_("n")
                 .order_by("n.sensitivity DESC")
                 .limit(10)
                 .build())
        
        self.assertIn("ORDER BY", query["query"])
        self.assertIn("LIMIT 10", query["query"])


class TestAttackPathQueryBuilder(unittest.TestCase):
    """Test attack path query construction"""

    def test_find_paths_from_attacker(self):
        query = AttackPathQueryBuilder.find_paths_from_attacker(
            attacker_id="ATK-001",
            target_id="AST-001",
            max_length=5
        )
        
        self.assertIn("MATCH path", query["query"])
        self.assertIn("ATK-001", query["params"].values())
        self.assertIn("AST-001", query["params"].values())

    def test_find_reachable_assets(self):
        query = AttackPathQueryBuilder.find_reachable_assets(
            attacker_id="ATK-EXTERNAL"
        )
        
        self.assertIn("MATCH", query["query"])
        self.assertIn("Asset", query["query"])

    def test_find_vulnerability_chains(self):
        query = AttackPathQueryBuilder.find_vulnerability_chains()
        
        self.assertIn("Precondition", query["query"])
        self.assertIn("Weakness", query["query"])


class TestPathScorer(unittest.TestCase):
    """Test attack path scoring"""

    def test_score_simple_path(self):
        nodes = [
            {"id": "A1", "type": "AttackerPosition"},
            {"id": "V1", "type": "Weakness", "cvss_score": 8.0},
            {"id": "A2", "type": "Asset", "sensitivity": "CRITICAL"}
        ]
        edges = [
            {"confidence": 0.9, "detection_probability": 0.2},
            {"confidence": 0.95, "detection_probability": 0.1}
        ]
        
        score = PathScorer.score_path(nodes, edges)
        
        self.assertGreater(score["overall_score"], 0)
        self.assertLessEqual(score["overall_score"], 10)
        self.assertIn("exploitability", score)
        self.assertIn("impact", score)

    def test_empty_path_scores_zero(self):
        score = PathScorer.score_path([], [])
        
        self.assertEqual(score["overall_score"], 0.0)

    def test_critical_asset_high_impact(self):
        # Need at least 2 nodes (start + asset) for scoring to work
        nodes = [
            {"id": "A0", "type": "AttackerPosition"},
            {"id": "A1", "type": "Asset", "sensitivity": "CRITICAL"}
        ]
        edges = [{"confidence": 0.9, "detection_probability": 0.1}]

        score = PathScorer.score_path(nodes, edges)
        self.assertGreater(score["impact"], 0.7)


class TestAttackPathFinder(unittest.TestCase):
    """Test attack path discovery"""

    def setUp(self):
        self.backend = InMemoryBackend()
        self.finder = AttackPathFinder(self.backend)

    def test_find_shortest_path(self):
        # Create a simple graph
        self.backend.add_node("N1", "Attacker", "External", {})
        self.backend.add_node("N2", "Weakness", "Vuln1", {})
        self.backend.add_node("N3", "Asset", "Data", {})
        
        self.backend.add_edge("N1", "N2", "Exploits", {"confidence": 0.9})
        self.backend.add_edge("N2", "N3", "Exploits", {"confidence": 0.95})
        
        path = self.finder.find_shortest_path("N1", "N3")
        
        self.assertIsNotNone(path)
        # Path should be: N1 -> N2 -> N3 (3 nodes)
        self.assertEqual(len(path.nodes), 3, f"Expected 3 nodes, got {path.nodes}")
        self.assertEqual(path.nodes[0], "N1")
        self.assertEqual(path.nodes[2], "N3")

    def test_no_path_returns_none(self):
        self.backend.add_node("N1", "Attacker", "A", {})
        self.backend.add_node("N2", "Asset", "B", {})
        
        path = self.finder.find_shortest_path("N1", "N2")
        
        self.assertIsNone(path)


class TestAdversaryModeler(unittest.TestCase):
    """Test adversary tier modeling"""

    def test_t1_filtered_by_exploitability(self):
        # T1 requires high exploitability
        path = AttackPath("P1", ["N1", "N2"], [])
        scoring = {"exploitability": 0.5, "impact": 0.5, "probability": 0.5}
        
        filtered = AdversaryModeler.filter_by_tier([(path, scoring)], "T1")
        
        # Should be filtered out (exploitability too low)
        self.assertEqual(len(filtered), 0)

    def test_t4_accepts_any_exploitability(self):
        path = AttackPath("P1", ["N1"] * 10, [])
        scoring = {"exploitability": 0.3, "impact": 0.5, "probability": 0.5}
        
        filtered = AdversaryModeler.filter_by_tier([(path, scoring)], "T4")
        
        # T4 should accept low exploitability
        self.assertGreater(len(filtered), 0)

    def test_tier_distribution(self):
        paths = [
            (AttackPath("P1", ["N1", "N2"], []), 
             {"exploitability": 0.9, "impact": 0.5, "probability": 0.8}),
            (AttackPath("P2", ["N1"] * 8, []), 
             {"exploitability": 0.4, "impact": 0.5, "probability": 0.6}),
        ]
        
        distribution = AdversaryModeler.get_exploitable_by_tiers(paths)
        
        self.assertIn("T1", distribution)
        self.assertIn("T4", distribution)
        self.assertGreaterEqual(len(distribution["T4"]), len(distribution["T1"]))


class TestThreatKGBuilder(unittest.TestCase):
    """Test threat knowledge graph construction"""

    def setUp(self):
        self.backend = InMemoryBackend()
        self.builder = ThreatKGBuilder(self.backend)

    def test_ingest_findings(self):
        findings = [
            {
                "id": "FD001",
                "call_name": "eval",
                "severity": "CRITICAL",
                "cwe_id": "CWE-95",
                "file": "app.py",
                "line": 42
            }
        ]
        
        result = self.builder.ingest_findings(findings)
        
        self.assertEqual(result["ingested"], 1)
        self.assertEqual(result["failed"], 0)

    def test_create_attacker_positions(self):
        result = self.builder.create_attacker_positions()
        
        self.assertGreaterEqual(result["created"], 4)

    def test_create_assets(self):
        assets = [
            {"id": "AST-001", "name": "database", "type": "DataStore", "sensitivity": "CRITICAL"}
        ]
        
        result = self.builder.create_assets(assets)
        
        self.assertEqual(result["created"], 1)


class TestThreatModelingPipeline(unittest.TestCase):
    """Test end-to-end threat modeling"""

    def setUp(self):
        self.backend = InMemoryBackend()
        self.pipeline = ThreatModelingPipeline(self.backend)

    def test_pipeline_runs(self):
        analysis_result = {
            "assets": [
                {"id": "AST-001", "name": "db", "type": "DataStore", "sensitivity": "CRITICAL"}
            ],
            "findings": [
                {"id": "FD001", "call_name": "eval", "severity": "HIGH", "cwe_id": "CWE-95"}
            ],
            "control_flow": {"file": "app.py", "functions": []},
            "taint_flows": [],
            "controls": []
        }
        
        result = self.pipeline.run(analysis_result)
        
        self.assertTrue(result["success"])
        self.assertIn("stages", result)
        self.assertIn("final_stats", result)

    def test_pipeline_records_all_stages(self):
        analysis_result = {
            "assets": [],
            "findings": [],
            "control_flow": {},
            "taint_flows": [],
            "controls": []
        }
        
        result = self.pipeline.run(analysis_result)
        
        stages = result["stages"]
        self.assertIn("attacker_positions", stages)
        self.assertIn("assets", stages)
        self.assertIn("findings", stages)


if __name__ == "__main__":
    unittest.main()