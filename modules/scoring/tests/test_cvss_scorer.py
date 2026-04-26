"""
MISTCODER -- CVSS Risk Scorer
Test Suite v0.1.0
"""

import os
import sys
import math
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                "..", "..", "ingestion", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                "..", "..", "analysis", "src"))

from cvss_scorer import (
    CVSSScorer,
    score_finding,
    _cvss_base_score,
    _cvss_vector_string,
    _severity_label,
    _context_score,
    _aggregate,
    _risk_vector,
    _risk_label,
    _asset_weight,
    CHAIN_AMPLIFIER,
    UNREACHABLE_DISCOUNT,
    CATEGORY_VECTORS,
    SEVERITY_BANDS,
)
from parser import PythonParser
from analysis_engine import AnalysisEngine

VULNERABLE_SOURCE = (
    "import os\n"
    "password = 'hunter2'\n"
    "api_key = 'sk-abc123'\n"
    "def run(cmd):\n"
    "    eval(cmd)\n"
    "    os.system(cmd)\n"
)

def make_findings(source=VULNERABLE_SOURCE):
    ir     = PythonParser(source, "test.py").parse()
    report = AnalysisEngine().analyze(ir)
    return report.get("findings", [])


# ---------------------------------------------------------------------------
# CVSS 3.1 base score calculation
# ---------------------------------------------------------------------------

class TestCVSSBaseScore(unittest.TestCase):

    def test_critical_rce_score(self):
        score = _cvss_base_score("N", "L", "N", "N", "C", "H", "H", "H")
        self.assertGreaterEqual(score, 9.0)

    def test_low_severity_score(self):
        score = _cvss_base_score("L", "H", "H", "R", "U", "N", "L", "N")
        self.assertLessEqual(score, 4.0)

    def test_score_bounded_0_to_10(self):
        score = _cvss_base_score("N", "L", "N", "N", "C", "H", "H", "H")
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 10.0)

    def test_zero_impact_returns_zero(self):
        score = _cvss_base_score("N", "L", "N", "N", "U", "N", "N", "N")
        self.assertEqual(score, 0.0)

    def test_scope_changed_scores_higher(self):
        unchanged = _cvss_base_score("N", "L", "N", "N", "U", "H", "H", "H")
        changed   = _cvss_base_score("N", "L", "N", "N", "C", "H", "H", "H")
        self.assertGreater(changed, unchanged)

    def test_network_vector_scores_higher_than_local(self):
        network = _cvss_base_score("N", "L", "N", "N", "U", "H", "H", "H")
        local   = _cvss_base_score("L", "L", "N", "N", "U", "H", "H", "H")
        self.assertGreater(network, local)

    def test_low_complexity_scores_higher_than_high(self):
        low  = _cvss_base_score("N", "L", "N", "N", "U", "H", "H", "H")
        high = _cvss_base_score("N", "H", "N", "N", "U", "H", "H", "H")
        self.assertGreater(low, high)

    def test_result_is_float(self):
        score = _cvss_base_score("N", "L", "N", "N", "U", "H", "L", "N")
        self.assertIsInstance(score, float)


# ---------------------------------------------------------------------------
# CVSS vector string
# ---------------------------------------------------------------------------

class TestCVSSVectorString(unittest.TestCase):

    def test_format_correct(self):
        v = _cvss_vector_string("N", "L", "N", "N", "C", "H", "H", "H")
        self.assertTrue(v.startswith("CVSS:3.1/AV:N"))

    def test_contains_all_metrics(self):
        v = _cvss_vector_string("N", "L", "N", "N", "C", "H", "H", "H")
        for metric in ("AV:", "AC:", "PR:", "UI:", "S:", "C:", "I:", "A:"):
            self.assertIn(metric, v)


# ---------------------------------------------------------------------------
# Severity labels
# ---------------------------------------------------------------------------

class TestSeverityLabel(unittest.TestCase):

    def test_critical(self):
        self.assertEqual(_severity_label(9.0), "CRITICAL")

    def test_high(self):
        self.assertEqual(_severity_label(7.5), "HIGH")

    def test_medium(self):
        self.assertEqual(_severity_label(5.0), "MEDIUM")

    def test_low(self):
        self.assertEqual(_severity_label(2.0), "LOW")

    def test_none(self):
        self.assertEqual(_severity_label(0.0), "NONE")

    def test_boundary_critical(self):
        self.assertEqual(_severity_label(9.0), "CRITICAL")

    def test_boundary_high(self):
        self.assertEqual(_severity_label(7.0), "HIGH")

    def test_boundary_medium(self):
        self.assertEqual(_severity_label(4.0), "MEDIUM")


# ---------------------------------------------------------------------------
# Context scoring
# ---------------------------------------------------------------------------

class TestContextScore(unittest.TestCase):

    def test_chain_amplifies_score(self):
        base     = _cvss_base_score("N", "L", "N", "N", "U", "H", "H", "H")
        normal   = _context_score(base, "DEFAULT", in_chain=False)
        chained  = _context_score(base, "DEFAULT", in_chain=True)
        self.assertGreater(chained, normal)

    def test_unreachable_discounts_score(self):
        base       = _cvss_base_score("N", "L", "N", "N", "U", "H", "H", "H")
        reachable  = _context_score(base, "DEFAULT", reachable=True)
        unreachable = _context_score(base, "DEFAULT", reachable=False)
        self.assertLess(unreachable, reachable)

    def test_asset_weight_increases_score(self):
        base     = _cvss_base_score("N", "L", "N", "N", "U", "H", "H", "H")
        normal   = _context_score(base, "DEFAULT")
        critical = _context_score(base, "SECRET_EXPOSURE")
        self.assertGreater(critical, normal)

    def test_score_capped_at_10(self):
        score = _context_score(10.0, "SECRET_EXPOSURE", in_chain=True)
        self.assertLessEqual(score, 10.0)

    def test_chain_multiplier_value(self):
        self.assertEqual(CHAIN_AMPLIFIER, 1.20)

    def test_unreachable_discount_value(self):
        self.assertEqual(UNREACHABLE_DISCOUNT, 0.70)


# ---------------------------------------------------------------------------
# Score finding
# ---------------------------------------------------------------------------

class TestScoreFinding(unittest.TestCase):

    def _make_finding(self, cat="DANGEROUS_CALL", fid="MIST-00001"):
        return {"id": fid, "category": cat,
                "description": "test", "line": 4, "severity": "high"}

    def test_returns_required_keys(self):
        sf = score_finding(self._make_finding())
        for key in ("finding_id", "category", "cvss_base_score",
                    "context_score", "severity", "cvss_vector",
                    "modifiers", "vector_detail"):
            self.assertIn(key, sf)

    def test_dangerous_call_is_critical(self):
        sf = score_finding(self._make_finding("DANGEROUS_CALL"))
        self.assertIn(sf["severity"], ("CRITICAL", "HIGH"))

    def test_chain_modifier_stored(self):
        sf = score_finding(self._make_finding(), in_chain=True)
        self.assertTrue(sf["modifiers"]["in_chain"])

    def test_unreachable_modifier_stored(self):
        sf = score_finding(self._make_finding(), reachable=False)
        self.assertFalse(sf["modifiers"]["reachable"])

    def test_context_score_gte_base_when_chained(self):
        sf = score_finding(self._make_finding(), in_chain=True)
        self.assertGreaterEqual(sf["context_score"], sf["cvss_base_score"] * 0.9)

    def test_unknown_category_uses_default_vector(self):
        sf = score_finding({"id": "X", "category": "TOTALLY_UNKNOWN",
                            "description": "x", "line": 1})
        self.assertIn("cvss_base_score", sf)
        self.assertGreaterEqual(sf["cvss_base_score"], 0.0)


# ---------------------------------------------------------------------------
# Aggregate score
# ---------------------------------------------------------------------------

class TestAggregateScore(unittest.TestCase):

    def test_empty_findings_zero(self):
        agg = _aggregate([])
        self.assertEqual(agg["score"], 0.0)
        self.assertEqual(agg["label"], "NONE")

    def test_single_critical_finding(self):
        sf  = score_finding({"id": "X", "category": "DANGEROUS_CALL",
                             "description": "x", "line": 1})
        agg = _aggregate([sf])
        self.assertGreater(agg["score"], 0.0)

    def test_more_findings_higher_aggregate(self):
        findings = [
            {"id": f"F{i}", "category": "EXCEPTION_SWALLOW",
             "description": "x", "line": i}
            for i in range(5)
        ]
        scored_1 = [score_finding(findings[0])]
        scored_5 = [score_finding(f) for f in findings]
        agg_1    = _aggregate(scored_1)
        agg_5    = _aggregate(scored_5)
        self.assertGreater(agg_5["score"], agg_1["score"])

    def test_aggregate_bounded_at_10(self):
        findings = [
            score_finding({"id": f"F{i}", "category": "EXCEPTION_SWALLOW",
                           "description": "x", "line": i})
            for i in range(20)
        ]
        agg = _aggregate(findings)
        self.assertLessEqual(agg["score"], 10.0)

    def test_severity_counts_sum_to_total(self):
        findings = [
            score_finding({"id": f"F{i}", "category": "DANGEROUS_CALL",
                           "description": "x", "line": i})
            for i in range(3)
        ]
        agg   = _aggregate(findings)
        total = (agg.get("critical", 0) + agg.get("high", 0) +
                 agg.get("medium", 0) + agg.get("low", 0))
        self.assertEqual(total, agg["finding_count"])


# ---------------------------------------------------------------------------
# Risk vector and label
# ---------------------------------------------------------------------------

class TestRiskVector(unittest.TestCase):

    def test_vector_format(self):
        agg = {"score": 8.5, "critical": 2, "high": 1,
               "medium": 0, "low": 0, "finding_count": 3}
        v   = _risk_vector(agg, [])
        self.assertTrue(v.startswith("MIST/AG:"))
        self.assertIn("/C:", v)
        self.assertIn("/H:", v)
        self.assertIn("/FC:", v)

    def test_risk_label_critical(self):
        label = _risk_label(9.5)
        self.assertIn("CRITICAL", label)

    def test_risk_label_high(self):
        label = _risk_label(7.5)
        self.assertIn("HIGH", label)

    def test_risk_label_none(self):
        label = _risk_label(0.0)
        self.assertIn("NONE", label)


# ---------------------------------------------------------------------------
# CVSSScorer integration
# ---------------------------------------------------------------------------

class TestCVSSScorerIntegration(unittest.TestCase):

    def setUp(self):
        self.findings = make_findings()
        self.scorer   = CVSSScorer()

    def test_score_returns_required_keys(self):
        result = self.scorer.score(self.findings)
        for key in ("scores", "aggregate", "risk_vector",
                    "risk_label", "metadata"):
            self.assertIn(key, result)

    def test_scores_list_length_matches_findings(self):
        result = self.scorer.score(self.findings)
        self.assertEqual(len(result["scores"]), len(self.findings))

    def test_sorted_by_context_score_descending(self):
        result = self.scorer.score(self.findings)
        scores = [s["context_score"] for s in result["scores"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_aggregate_score_positive(self):
        result = self.scorer.score(self.findings)
        self.assertGreater(result["aggregate"]["score"], 0.0)

    def test_chain_amplification_applied(self):
        if not self.findings:
            return
        fid    = self.findings[0].get("id", "")
        chains = [{"id": "CH-0001", "links": [fid],
                   "combined_severity": "critical", "confidence": 0.9}]
        base   = self.scorer.score(self.findings)
        chained = self.scorer.score(self.findings, chains=chains)
        base_score    = next((s["context_score"] for s in base["scores"]
                              if s["finding_id"] == fid), 0)
        chained_score = next((s["context_score"] for s in chained["scores"]
                              if s["finding_id"] == fid), 0)
        self.assertGreaterEqual(chained_score, base_score)

    def test_metadata_has_standard(self):
        result = self.scorer.score(self.findings)
        self.assertEqual(result["metadata"]["standard"], "CVSS 3.1")

    def test_metadata_has_timestamp(self):
        result = self.scorer.score(self.findings)
        self.assertIn("scored_at", result["metadata"])

    def test_empty_findings_zero_aggregate(self):
        result = self.scorer.score([])
        self.assertEqual(result["aggregate"]["score"], 0.0)

    def test_risk_vector_string_present(self):
        result = self.scorer.score(self.findings)
        self.assertTrue(result["risk_vector"].startswith("MIST/AG:"))

    def test_risk_label_string_present(self):
        result = self.scorer.score(self.findings)
        self.assertIsInstance(result["risk_label"], str)
        self.assertGreater(len(result["risk_label"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
