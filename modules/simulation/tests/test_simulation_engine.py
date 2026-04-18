"""
MISTCODER -- Simulation Engine
Test Suite v0.1.0
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                "..", "..", "ingestion", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                "..", "..", "analysis", "src"))

from simulation_engine import (
    SimulationEngine, simulate,
    _score_outcome, _simulate_finding, _simulate_chain,
    _get_payloads, _get_impact,
    DEPTH_SEVERITY_FILTER, DEPTH_SCENARIO_FILTER,
    POC_PAYLOADS, CATEGORY_TO_SCENARIO,
)
from parser import PythonParser
from analysis_engine import AnalysisEngine

SAMPLE_SOURCE = (
    "import os\n"
    "password = 'hunter2'\n"
    "def login(user, raw):\n"
    "    eval(raw)\n"
    "    os.system(raw)\n"
)

def make_pipeline(source=SAMPLE_SOURCE):
    ir     = PythonParser(source, "test.py").parse()
    report = AnalysisEngine().analyze(ir)
    return ir, report

def make_reasoning_stub():
    return {
        "chains": [
            {
                "id":                "CH-0001",
                "combined_severity": "critical",
                "confidence":        0.90,
                "narrative":         "Credential bypasses auth, reaches eval().",
                "links":             ["MIST-00001", "MIST-00002"],
            }
        ],
        "attack_paths": [],
        "anomalies":    [],
        "metadata":     {},
    }


class TestDepthControl(unittest.TestCase):

    def test_low_only_critical(self):
        self.assertIn("critical", DEPTH_SEVERITY_FILTER["LOW"])
        self.assertNotIn("high", DEPTH_SEVERITY_FILTER["LOW"])

    def test_medium_includes_high(self):
        self.assertIn("high", DEPTH_SEVERITY_FILTER["MEDIUM"])

    def test_high_includes_medium_low(self):
        self.assertIn("medium", DEPTH_SEVERITY_FILTER["HIGH"])
        self.assertIn("low",    DEPTH_SEVERITY_FILTER["HIGH"])

    def test_low_scenario_filter_restricted(self):
        self.assertNotIn("PRIVESC",   DEPTH_SCENARIO_FILTER["LOW"])
        self.assertNotIn("INJECTION", DEPTH_SCENARIO_FILTER["LOW"])

    def test_high_scenario_filter_includes_chain(self):
        self.assertIn("CHAIN", DEPTH_SCENARIO_FILTER["HIGH"])

    def test_invalid_depth_raises(self):
        ir, report = make_pipeline()
        with self.assertRaises(ValueError):
            simulate(ir, report, depth="EXTREME")


class TestOutcomeScoring(unittest.TestCase):

    def test_critical_high_conf_is_success(self):
        self.assertEqual(_score_outcome("critical", 0.90), "SUCCESS")

    def test_high_high_conf_is_success(self):
        self.assertEqual(_score_outcome("high", 0.80), "SUCCESS")

    def test_medium_mid_conf_is_partial(self):
        self.assertEqual(_score_outcome("medium", 0.55), "PARTIAL")

    def test_low_low_conf_is_blocked(self):
        self.assertEqual(_score_outcome("low", 0.20), "BLOCKED")

    def test_critical_low_conf_is_partial(self):
        self.assertEqual(_score_outcome("critical", 0.40), "PARTIAL")


class TestPayloads(unittest.TestCase):

    def test_dangerous_call_has_payloads(self):
        p = _get_payloads("DANGEROUS_CALL")
        self.assertGreater(len(p), 0)
        self.assertTrue(any("import" in x or "eval" in x.lower() for x in p))

    def test_command_injection_has_payloads(self):
        p = _get_payloads("COMMAND_INJECTION")
        self.assertTrue(any("id" in x or "whoami" in x for x in p))

    def test_sql_injection_has_payloads(self):
        p = _get_payloads("SQL_INJECTION")
        self.assertTrue(any("OR" in x or "UNION" in x for x in p))

    def test_unknown_category_returns_default(self):
        p = _get_payloads("TOTALLY_UNKNOWN_CATEGORY")
        self.assertEqual(p, POC_PAYLOADS["DEFAULT"])

    def test_hardcoded_secret_payload_is_informational(self):
        p = _get_payloads("HARDCODED_SECRET")
        self.assertTrue(any("CREDENTIAL" in x.upper() for x in p))


class TestSimulateFinding(unittest.TestCase):

    def _make_finding(self, sev="critical", cat="DANGEROUS_CALL"):
        return {"id": "MIST-00001", "severity": sev,
                "category": cat, "description": "test", "line": 4}

    def test_returns_dict_with_required_keys(self):
        result = _simulate_finding(self._make_finding(), "RCE", "SIM-0001")
        for key in ("id", "finding_id", "scenario_type", "severity",
                    "confidence", "outcome", "outcome_label", "impact", "payloads"):
            self.assertIn(key, result)

    def test_critical_finding_success_outcome(self):
        result = _simulate_finding(self._make_finding("critical"), "RCE", "SIM-0001")
        self.assertEqual(result["outcome"], "SUCCESS")

    def test_low_finding_blocked_outcome(self):
        result = _simulate_finding(self._make_finding("low"), "DATA_EXFIL", "SIM-0002")
        self.assertEqual(result["outcome"], "BLOCKED")

    def test_scenario_type_stored(self):
        result = _simulate_finding(self._make_finding(), "INJECTION", "SIM-0003")
        self.assertEqual(result["scenario_type"], "INJECTION")

    def test_payloads_not_empty(self):
        result = _simulate_finding(self._make_finding(), "RCE", "SIM-0004")
        self.assertGreater(len(result["payloads"]), 0)


class TestSimulateChain(unittest.TestCase):

    def _make_chain(self, sev="critical", conf=0.90):
        return {
            "id":                "CH-0001",
            "combined_severity": sev,
            "confidence":        conf,
            "narrative":         "Test chain.",
            "links":             ["MIST-00001"],
        }

    def _findings_map(self):
        return {"MIST-00001": {"id": "MIST-00001", "category": "DANGEROUS_CALL",
                               "severity": "critical", "description": "eval"}}

    def test_chain_returns_required_keys(self):
        result = _simulate_chain(self._make_chain(), self._findings_map(), "SIM-0001")
        for key in ("id", "chain_id", "scenario_type", "outcome",
                    "outcome_label", "impact", "narrative", "payloads", "links"):
            self.assertIn(key, result)

    def test_chain_scenario_type_is_chain(self):
        result = _simulate_chain(self._make_chain(), self._findings_map(), "SIM-0001")
        self.assertEqual(result["scenario_type"], "CHAIN")

    def test_critical_chain_high_conf_is_success(self):
        result = _simulate_chain(self._make_chain("critical", 0.90),
                                 self._findings_map(), "SIM-0001")
        self.assertEqual(result["outcome"], "SUCCESS")

    def test_chain_payloads_capped_at_four(self):
        findings_map = {
            f"MIST-0000{i}": {"id": f"MIST-0000{i}", "category": "DANGEROUS_CALL",
                              "severity": "high", "description": "x"}
            for i in range(1, 6)
        }
        chain = {
            "id": "CH-0001", "combined_severity": "high",
            "confidence": 0.8, "narrative": "x",
            "links": [f"MIST-0000{i}" for i in range(1, 6)],
        }
        result = _simulate_chain(chain, findings_map, "SIM-0001")
        self.assertLessEqual(len(result["payloads"]), 4)


class TestSimulateIntegration(unittest.TestCase):

    def setUp(self):
        self.ir, self.report = make_pipeline()
        self.reasoning       = make_reasoning_stub()

    def test_simulate_returns_dict(self):
        result = simulate(self.ir, self.report)
        self.assertIsInstance(result, dict)

    def test_result_has_required_keys(self):
        result = simulate(self.ir, self.report)
        for key in ("simulations", "summary", "metadata"):
            self.assertIn(key, result)

    def test_summary_counts_correct(self):
        result = simulate(self.ir, self.report, depth="HIGH")
        s = result["summary"]
        self.assertEqual(s["total"], s["success"] + s["partial"] + s["blocked"])

    def test_depth_low_filters_non_critical(self):
        result = simulate(self.ir, self.report, depth="LOW")
        for sim in result["simulations"]:
            self.assertEqual(sim.get("severity"), "critical")

    def test_depth_medium_excludes_privesc(self):
        result = simulate(self.ir, self.report, depth="MEDIUM")
        for sim in result["simulations"]:
            self.assertNotEqual(sim.get("scenario_type"), "PRIVESC")

    def test_depth_high_includes_chains(self):
        result = simulate(self.ir, self.report, self.reasoning, depth="HIGH")
        types = [s["scenario_type"] for s in result["simulations"]]
        self.assertIn("CHAIN", types)

    def test_metadata_has_depth(self):
        result = simulate(self.ir, self.report, depth="MEDIUM")
        self.assertEqual(result["metadata"]["depth"], "MEDIUM")

    def test_metadata_has_timestamp(self):
        result = simulate(self.ir, self.report)
        self.assertIn("simulated_at", result["metadata"])

    def test_empty_findings_returns_empty_simulations(self):
        empty_report = {"findings": [], "metadata": {}}
        result = simulate(self.ir, empty_report)
        self.assertEqual(result["simulations"], [])
        self.assertEqual(result["summary"]["total"], 0)

    def test_simulation_engine_class_interface(self):
        engine = SimulationEngine(depth="MEDIUM")
        result = engine.simulate(self.ir, self.report)
        self.assertIn("simulations", result)

    def test_simulation_engine_default_depth_medium(self):
        engine = SimulationEngine()
        self.assertEqual(engine.depth, "MEDIUM")

    def test_each_simulation_has_payloads(self):
        result = simulate(self.ir, self.report, depth="HIGH")
        for sim in result["simulations"]:
            self.assertIn("payloads", sim)
            self.assertIsInstance(sim["payloads"], list)

    def test_sim_ids_are_unique(self):
        result = simulate(self.ir, self.report, self.reasoning, depth="HIGH")
        ids = [s["id"] for s in result["simulations"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_impact_field_present_and_nonempty(self):
        result = simulate(self.ir, self.report, depth="HIGH")
        for sim in result["simulations"]:
            self.assertTrue(len(sim["impact"]) > 0)

    def test_confidence_between_zero_and_one(self):
        result = simulate(self.ir, self.report, depth="HIGH")
        for sim in result["simulations"]:
            self.assertGreaterEqual(sim["confidence"], 0.0)
            self.assertLessEqual(sim["confidence"], 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
