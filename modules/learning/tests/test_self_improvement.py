"""
MISTCODER -- Self-Improvement Core
Test Suite v0.1.0
"""

import os
import sys
import json
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cve_ingester        import CVEIngester, _parse_nvd_item, _extract_patterns, _extract_categories, CWE_CATEGORY_MAP
from knowledge_base      import KnowledgeBase, DEFAULT_CATEGORY_WEIGHTS
from pattern_learner     import PatternLearner, SINK_PATTERNS
from self_improvement_core import SelfImprovementCore, ImprovementCycle, REVIEW_GATE_THRESHOLDS


def tmp_kb():
    f = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    path = f.name
    f.close()
    return KnowledgeBase(kb_path=path)

def tmp_sic():
    td  = tempfile.mkdtemp()
    kb  = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    kb.close()
    sic = SelfImprovementCore(kb_path=kb.name, cache_dir=td)
    return sic

SYNTHETIC_CVE = {
    "cve_id": "CVE-2024-TEST-001",
    "description": "Remote code execution via eval() on unsanitized input.",
    "cvss_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "severity": "CRITICAL",
    "cwe_ids": ["CWE-95"],
    "affected": ["python/flask"],
    "published": "2024-01-01T00:00:00.000",
    "patterns": ["eval", "exec"],
    "categories": ["DANGEROUS_CALL"],
}


# ---------------------------------------------------------------------------
# CVEIngester
# ---------------------------------------------------------------------------

class TestCVEIngester(unittest.TestCase):

    def setUp(self):
        self.td      = tempfile.mkdtemp()
        self.ingester = CVEIngester(cache_dir=self.td)

    def test_load_synthetic_returns_list(self):
        records = self.ingester.load_synthetic()
        self.assertIsInstance(records, list)

    def test_synthetic_has_minimum_records(self):
        records = self.ingester.load_synthetic()
        self.assertGreaterEqual(len(records), 8)

    def test_synthetic_record_has_required_keys(self):
        records = self.ingester.load_synthetic()
        for r in records:
            for key in ("cve_id", "description", "cvss_score",
                        "severity", "cwe_ids", "patterns", "categories"):
                self.assertIn(key, r)

    def test_synthetic_all_have_cve_ids(self):
        records = self.ingester.load_synthetic()
        for r in records:
            self.assertTrue(r["cve_id"].startswith("CVE-"))

    def test_synthetic_cvss_scores_in_range(self):
        records = self.ingester.load_synthetic()
        for r in records:
            self.assertGreaterEqual(r["cvss_score"], 0.0)
            self.assertLessEqual(r["cvss_score"], 10.0)

    def test_synthetic_categories_are_lists(self):
        records = self.ingester.load_synthetic()
        for r in records:
            self.assertIsInstance(r["categories"], list)

    def test_cache_roundtrip(self):
        records = self.ingester.load_synthetic()
        self.ingester._save_cache("test_key", records)
        loaded  = self.ingester._load_cache("test_key")
        self.assertEqual(len(loaded), len(records))

    def test_cache_miss_returns_none(self):
        result = self.ingester._load_cache("nonexistent_key_xyz")
        self.assertIsNone(result)

    def test_extract_patterns_finds_eval(self):
        patterns = _extract_patterns("eval() called on user input")
        self.assertIn("eval", patterns)

    def test_extract_patterns_finds_pickle(self):
        patterns = _extract_patterns("insecure use of pickle deserialization")
        self.assertIn("pickle", patterns)

    def test_extract_categories_from_cwe(self):
        categories = _extract_categories("SQL injection", ["CWE-89"])
        self.assertIn("SQL_INJECTION", categories)

    def test_extract_categories_from_keywords(self):
        categories = _extract_categories("remote code execution via eval", [])
        self.assertIn("DANGEROUS_CALL", categories)

    def test_cwe_map_covers_common_cwes(self):
        for cwe in ("CWE-78", "CWE-89", "CWE-79", "CWE-502", "CWE-798"):
            self.assertIn(cwe, CWE_CATEGORY_MAP)


# ---------------------------------------------------------------------------
# KnowledgeBase
# ---------------------------------------------------------------------------

class TestKnowledgeBase(unittest.TestCase):

    def setUp(self):
        self.kb = tmp_kb()

    def test_add_cve_returns_true_for_new(self):
        result = self.kb.add_cve(SYNTHETIC_CVE)
        self.assertTrue(result)

    def test_add_cve_returns_false_for_duplicate(self):
        self.kb.add_cve(SYNTHETIC_CVE)
        result = self.kb.add_cve(SYNTHETIC_CVE)
        self.assertFalse(result)

    def test_get_cve_returns_record(self):
        self.kb.add_cve(SYNTHETIC_CVE)
        r = self.kb.get_cve("CVE-2024-TEST-001")
        self.assertIsNotNone(r)
        self.assertEqual(r["cve_id"], "CVE-2024-TEST-001")

    def test_add_cves_returns_new_count(self):
        records = [dict(SYNTHETIC_CVE, cve_id=f"CVE-TEST-{i}")
                   for i in range(5)]
        count = self.kb.add_cves(records)
        self.assertEqual(count, 5)

    def test_cves_by_category(self):
        self.kb.add_cve(SYNTHETIC_CVE)
        results = self.kb.cves_by_category("DANGEROUS_CALL")
        self.assertGreater(len(results), 0)

    def test_add_pattern_stores_pattern(self):
        self.kb.add_pattern("eval(", "DANGEROUS_CALL", confidence=0.9)
        patterns = self.kb.get_patterns(min_confidence=0.5)
        self.assertTrue(any(p["pattern"] == "eval(" for p in patterns))

    def test_pattern_confidence_increases_on_repeat(self):
        self.kb.add_pattern("exec(", "DANGEROUS_CALL", confidence=0.5)
        conf1 = self.kb.get_patterns()[0]["confidence"]
        self.kb.add_pattern("exec(", "DANGEROUS_CALL", confidence=0.5)
        conf2 = self.kb.get_patterns()[0]["confidence"]
        self.assertGreaterEqual(conf2, conf1)

    def test_get_weight_returns_default(self):
        w = self.kb.get_weight("DANGEROUS_CALL")
        self.assertEqual(w, DEFAULT_CATEGORY_WEIGHTS["DANGEROUS_CALL"])

    def test_update_weight_bounded_max(self):
        for _ in range(50):
            self.kb.update_weight("DANGEROUS_CALL", +0.10)
        w = self.kb.get_weight("DANGEROUS_CALL")
        self.assertLessEqual(w, 2.0)

    def test_update_weight_bounded_min(self):
        for _ in range(50):
            self.kb.update_weight("DANGEROUS_CALL", -0.10)
        w = self.kb.get_weight("DANGEROUS_CALL")
        self.assertGreaterEqual(w, 0.5)

    def test_add_dangerous_call(self):
        self.kb.add_dangerous_call("os.execvp")
        self.assertIn("os.execvp", self.kb.get_dangerous_calls())

    def test_no_duplicate_dangerous_calls(self):
        self.kb.add_dangerous_call("custom_exec")
        self.kb.add_dangerous_call("custom_exec")
        calls = self.kb.get_dangerous_calls()
        self.assertEqual(calls.count("custom_exec"), 1)

    def test_add_secret_keyword(self):
        self.kb.add_secret_keyword("vault_token")
        self.assertIn("vault_token", self.kb.get_secret_keywords())

    def test_add_sink(self):
        self.kb.add_sink("python", "custom_db.execute")
        self.assertIn("custom_db.execute", self.kb.get_sinks("python"))

    def test_record_update_returns_id(self):
        uid = self.kb.record_update("test_update", {"key": "val"})
        self.assertIsInstance(uid, str)
        self.assertGreater(len(uid), 0)

    def test_stats_has_required_keys(self):
        st = self.kb.stats()
        for key in ("version", "cve_count", "pattern_count",
                    "update_count", "last_updated"):
            self.assertIn(key, st)

    def test_save_and_reload(self):
        self.kb.add_cve(SYNTHETIC_CVE)
        self.kb.add_pattern("test_pattern", "DANGEROUS_CALL", 0.8)
        self.kb.save()
        kb2 = KnowledgeBase(kb_path=self.kb.kb_path)
        self.assertEqual(kb2.stats()["cve_count"], 1)

    def test_record_feedback(self):
        findings = [{"id": "F1", "category": "DANGEROUS_CALL"}]
        self.kb.record_feedback("test.py", findings, true_positives=1)
        st = self.kb.stats()
        self.assertEqual(st["feedback_entries"], 1)


# ---------------------------------------------------------------------------
# PatternLearner
# ---------------------------------------------------------------------------

class TestPatternLearner(unittest.TestCase):

    def setUp(self):
        self.kb      = tmp_kb()
        self.learner = PatternLearner(self.kb)

    def test_learn_from_cves_returns_summary(self):
        cves   = CVEIngester(cache_dir=tempfile.mkdtemp()).load_synthetic()
        result = self.learner.learn_from_cves(cves)
        for key in ("update_id", "cves_processed", "patterns_added"):
            self.assertIn(key, result)

    def test_learn_from_cves_adds_patterns(self):
        cves   = CVEIngester(cache_dir=tempfile.mkdtemp()).load_synthetic()
        before = len(self.kb.get_patterns())
        self.learner.learn_from_cves(cves)
        after  = len(self.kb.get_patterns())
        self.assertGreater(after, before)

    def test_learn_from_cves_updates_weights(self):
        cves    = CVEIngester(cache_dir=tempfile.mkdtemp()).load_synthetic()
        before  = self.kb.get_weight("DANGEROUS_CALL")
        self.learner.learn_from_cves(cves)
        after   = self.kb.get_weight("DANGEROUS_CALL")
        self.assertGreaterEqual(after, before)

    def test_learn_from_cves_adds_dangerous_calls(self):
        cves   = CVEIngester(cache_dir=tempfile.mkdtemp()).load_synthetic()
        before = len(self.kb.get_dangerous_calls())
        self.learner.learn_from_cves(cves)
        after  = len(self.kb.get_dangerous_calls())
        self.assertGreaterEqual(after, before)

    def test_learn_from_scan_returns_summary(self):
        findings = [
            {"id": "F1", "category": "DANGEROUS_CALL",
             "description": "eval called", "severity": "high"}
        ]
        result = self.learner.learn_from_scan(findings, "test.py")
        self.assertIn("update_id", result)
        self.assertIn("findings_seen", result)

    def test_learn_from_scan_empty_findings(self):
        result = self.learner.learn_from_scan([], "test.py")
        self.assertEqual(result.get("learned", 0), 0)

    def test_export_detection_config_has_keys(self):
        config = self.learner.export_detection_config()
        for key in ("dangerous_calls", "secret_keywords",
                    "sinks_python", "sinks_javascript",
                    "category_weights", "high_conf_patterns"):
            self.assertIn(key, config)

    def test_export_detection_config_dangerous_calls_populated(self):
        config = self.learner.export_detection_config()
        self.assertGreater(len(config["dangerous_calls"]), 0)

    def test_export_detection_config_secret_keywords_populated(self):
        config = self.learner.export_detection_config()
        self.assertGreater(len(config["secret_keywords"]), 0)

    def test_sink_patterns_cover_python_and_js(self):
        self.assertIn("python", SINK_PATTERNS)
        self.assertIn("javascript", SINK_PATTERNS)


# ---------------------------------------------------------------------------
# SelfImprovementCore
# ---------------------------------------------------------------------------

class TestSelfImprovementCore(unittest.TestCase):

    def setUp(self):
        self.sic = tmp_sic()

    def test_run_cycle_synthetic_returns_dict(self):
        result = self.sic.run_cycle(mode="synthetic", verbose=False)
        self.assertIsInstance(result, dict)

    def test_run_cycle_has_cycle_id(self):
        result = self.sic.run_cycle(mode="synthetic", verbose=False)
        self.assertIn("cycle_id", result)
        self.assertTrue(result["cycle_id"].startswith("CYCLE-"))

    def test_run_cycle_has_stages(self):
        result = self.sic.run_cycle(mode="synthetic", verbose=False)
        self.assertIn("stages", result)
        self.assertGreater(len(result["stages"]), 0)

    def test_run_cycle_has_summary(self):
        result = self.sic.run_cycle(mode="synthetic", verbose=False)
        self.assertIn("summary", result)

    def test_run_cycle_increases_cve_count(self):
        before = self.sic.kb_stats()["cve_count"]
        self.sic.run_cycle(mode="synthetic", verbose=False)
        after  = self.sic.kb_stats()["cve_count"]
        self.assertGreater(after, before)

    def test_run_cycle_increases_pattern_count(self):
        before = self.sic.kb_stats()["pattern_count"]
        self.sic.run_cycle(mode="synthetic", verbose=False)
        after  = self.sic.kb_stats()["pattern_count"]
        self.assertGreater(after, before)

    def test_second_cycle_does_not_duplicate_cves(self):
        self.sic.run_cycle(mode="synthetic", verbose=False)
        after1 = self.sic.kb_stats()["cve_count"]
        self.sic.run_cycle(mode="synthetic", verbose=False)
        after2 = self.sic.kb_stats()["cve_count"]
        self.assertEqual(after1, after2)

    def test_feedback_mode_runs_without_cves(self):
        findings = [{"id": "F1", "category": "DANGEROUS_CALL",
                     "description": "eval", "severity": "high"}]
        result = self.sic.run_cycle(
            mode="feedback",
            scan_findings=findings,
            verbose=False
        )
        self.assertIn("cycle_id", result)

    def test_history_returns_list(self):
        self.sic.run_cycle(mode="synthetic", verbose=False)
        h = self.sic.history()
        self.assertIsInstance(h, list)
        self.assertGreater(len(h), 0)

    def test_cycle_ids_increment(self):
        r1 = self.sic.run_cycle(mode="synthetic", verbose=False)
        r2 = self.sic.run_cycle(mode="synthetic", verbose=False)
        self.assertNotEqual(r1["cycle_id"], r2["cycle_id"])

    def test_detection_config_exported(self):
        self.sic.run_cycle(mode="synthetic", verbose=False)
        config = self.sic.detection_config()
        self.assertGreater(len(config["dangerous_calls"]), 0)

    def test_review_gate_thresholds_exist(self):
        for key in ("weight_delta_max", "pattern_batch_max", "cve_batch_max"):
            self.assertIn(key, REVIEW_GATE_THRESHOLDS)

    def test_improvement_cycle_to_dict(self):
        cycle = ImprovementCycle("CYCLE-TEST", "synthetic")
        cycle.add_stage("test_stage", {"key": "val"})
        cycle.complete({"done": True})
        d = cycle.to_dict()
        for key in ("cycle_id", "mode", "stages", "summary",
                    "started_at", "completed_at"):
            self.assertIn(key, d)

    def test_kb_stats_after_cycle(self):
        self.sic.run_cycle(mode="synthetic", verbose=False)
        st = self.sic.kb_stats()
        for key in ("cve_count", "pattern_count", "update_count"):
            self.assertIn(key, st)


if __name__ == "__main__":
    unittest.main(verbosity=2)
