"""
MISTCODER MOD-07 Tests — Neo4j and In-Memory Backends
"""
import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from neo4j_backend import NeoBackend, InMemoryBackend, create_backend


class TestInMemoryBackend(unittest.TestCase):
    """Tests for in-memory backend (always available)"""

    def setUp(self):
        self.backend = InMemoryBackend()

    def test_add_node(self):
        result = self.backend.add_node("N001", "Asset", "database", {"sensitivity": "HIGH"})
        self.assertTrue(result)

    def test_find_node(self):
        self.backend.add_node("N001", "Asset", "database", {})
        node = self.backend.find_node("N001")
        self.assertIsNotNone(node)
        self.assertEqual(node["name"], "database")

    def test_add_edge(self):
        self.backend.add_node("N001", "Asset", "db", {})
        self.backend.add_node("N002", "Weakness", "sqli", {})
        result = self.backend.add_edge("N002", "N001", "Exploits", {"confidence": 0.9})
        self.assertTrue(result)

    def test_find_nodes_by_type(self):
        self.backend.add_node("A001", "Asset", "db1", {})
        self.backend.add_node("A002", "Asset", "db2", {})
        self.backend.add_node("W001", "Weakness", "sqli", {})
        
        assets = self.backend.find_nodes_by_type("Asset")
        self.assertEqual(len(assets), 2)

    def test_find_paths_linear(self):
        # Create a linear path: N1 -> N2 -> N3
        self.backend.add_node("N1", "Attacker", "External", {})
        self.backend.add_node("N2", "Weakness", "Vuln", {})
        self.backend.add_node("N3", "Asset", "Data", {})
        self.backend.add_edge("N1", "N2", "Exploits", {})
        self.backend.add_edge("N2", "N3", "Exploits", {})
        
        paths = self.backend.find_paths("N1", "N3")
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0], ["N1", "N2", "N3"])

    def test_reachable_from(self):
        self.backend.add_node("N1", "Attacker", "External", {})
        self.backend.add_node("N2", "Weakness", "Vuln1", {})
        self.backend.add_node("N3", "Weakness", "Vuln2", {})
        self.backend.add_edge("N1", "N2", "Exploits", {})
        self.backend.add_edge("N2", "N3", "Enables", {})
        
        reachable = self.backend.reachable_from("N1")
        reachable_ids = [n["id"] for n in reachable]
        self.assertIn("N2", reachable_ids)
        self.assertIn("N3", reachable_ids)

    def test_get_stats(self):
        self.backend.add_node("N1", "Asset", "db", {})
        self.backend.add_node("N2", "Weakness", "sqli", {})
        self.backend.add_edge("N2", "N1", "Exploits", {})
        
        stats = self.backend.get_stats()
        self.assertEqual(stats["node_count"], 2)
        self.assertEqual(stats["edge_count"], 1)

    def test_multiple_paths(self):
        # Create diamond: N1 -> N2 -> N4 and N1 -> N3 -> N4
        self.backend.add_node("N1", "Attacker", "External", {})
        self.backend.add_node("N2", "Weakness", "Vuln1", {})
        self.backend.add_node("N3", "Weakness", "Vuln2", {})
        self.backend.add_node("N4", "Asset", "Data", {})
        
        self.backend.add_edge("N1", "N2", "Exploits", {})
        self.backend.add_edge("N1", "N3", "Exploits", {})
        self.backend.add_edge("N2", "N4", "Exploits", {})
        self.backend.add_edge("N3", "N4", "Exploits", {})
        
        paths = self.backend.find_paths("N1", "N4", max_length=3)
        self.assertGreaterEqual(len(paths), 2)


class TestAutoSelectBackend(unittest.TestCase):
    """Test backend auto-selection logic"""

    def test_fallback_to_inmemory(self):
        # This will use in-memory since Neo4j likely isn't running
        backend = create_backend(prefer_neo4j=True)
        self.assertIsNotNone(backend)
        # Check that we got one of the backends
        self.assertTrue(
            backend.__class__.__name__ in ["NeoBackend", "InMemoryBackend"]
        )

    def test_explicit_inmemory(self):
        backend = create_backend(prefer_neo4j=False)
        self.assertIsInstance(backend, InMemoryBackend)


class TestAttackPathScenarios(unittest.TestCase):
    """Test realistic attack path scenarios"""

    def setUp(self):
        self.backend = InMemoryBackend()

    def test_web_app_attack_chain(self):
        """
        Realistic scenario: External attacker exploits input validation flaw,
        uses that to access admin panel, escalates to database access
        """
        # Create nodes
        self.backend.add_node("ATK-EXT", "AttackerPosition", "External", {})
        self.backend.add_node("VUL-INPUT", "Weakness", "Input Validation", {"cvss": 6.5})
        self.backend.add_node("ADMIN-PANEL", "Asset", "Admin Panel", {})
        self.backend.add_node("VUL-PRIV-ESC", "Weakness", "Privilege Escalation", {"cvss": 8.2})
        self.backend.add_node("DATABASE", "Asset", "Production DB", {"sensitivity": "CRITICAL"})

        # Create attack chain
        self.backend.add_edge("ATK-EXT", "VUL-INPUT", "Exploits", {"confidence": 0.85})
        self.backend.add_edge("VUL-INPUT", "ADMIN-PANEL", "Enables", {"confidence": 0.9})
        self.backend.add_edge("ADMIN-PANEL", "VUL-PRIV-ESC", "Exploits", {"confidence": 0.8})
        self.backend.add_edge("VUL-PRIV-ESC", "DATABASE", "Exploits", {"confidence": 0.95})

        # Find the full chain
        paths = self.backend.find_paths("ATK-EXT", "DATABASE", max_length=5)
        self.assertGreater(len(paths), 0)
        
        # Verify the chain length
        self.assertEqual(len(paths[0]), 5)  # ATK -> VUL1 -> ASSET1 -> VUL2 -> ASSET2


if __name__ == "__main__":
    unittest.main()