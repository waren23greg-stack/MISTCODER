"""
MISTCODER -- Report Generator
Test Suite v0.1.0
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                "..", "..", "ingestion", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                "..", "..", "analysis", "src"))

from report_generator import (
    ReportGenerator, generate,
    _badge, _e, _findings_table,
    _chains_section, _anomalies_section,
    SEVERITY_ORDER, BADGE
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


def make_pipeline(source="x = 1\n"):
    ir     = PythonParser(source, "test.py").parse()
    report = AnalysisEngine().analyze(ir)
    return ir, report


def make_reasoning_stub(risk="medium"):
    return {
        "threat_model": {
            "overall_risk":      risk,
            "attack_path_count": 2,
            "chain_count":       1,
            "anomaly_count":     0,
            "critical_paths":    0,
            "high_paths":        1,
            "critical_chains":   0,
        },
        "chains": [
            {
                "id":                "CH-0001",
                "combined_severity": "high",
                "narrative":         "Test chain narrative.",
                "confidence":        0.82,
                "links":             ["MIST-00001", "MIST-00002"]
            }
        ],
        "attack_paths": [
            {
                "id":          "AP-0001",
                "severity":    "high",
                "confidence":  0.75,
                "description": "Test path description.",
                "nodes":       ["N1", "N2", "N3"]
            }
        ],
        "anomalies": [],
        "metadata": {
            "graph_node_count":  10,
            "graph_edge_count":  8,
            "attack_path_count": 2,
            "chain_count":       1,
            "anomaly_count":     0,
            "overall_risk":      risk,
            "reasoner":          "ReasoningCore v0.1.0",
            "reasoned_at":       "2025-01-01T00:00:00+00:00"
        }
    }


class TestHelpers(unittest.TestCase):

    def test_e_escapes_html(self):
        self.assertIn("&lt;", _e("<script>"))
        self.assertIn("&amp;", _e("a&b"))

    def test_e_none_returns_empty(self):
        self.assertEqual(_e(None), "")

    def test_badge_returns_span(self):
        b = _badge("critical")
        self.assertIn("<span", b)
        self.assertIn("critical", b)

    def test_badge_all_severities(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            b = _badge(sev)
            self.assertIn(sev, b)

    def test_severity_order_critical_first(self):
        self.assertLess(
            SEVERITY_ORDER["critical"],
            SEVERITY_ORDER["high"]
        )

    def test_severity_order_info_last(self):
        self.assertEqual(SEVERITY_ORDER["info"], 4)


class TestFindingsTable(unittest.TestCase):

    def test_empty_findings_returns_message(self):
        result = _findings_table([])
        self.assertIn("No findings", result)

    def test_table_has_headers(self):
        findings = [{"id": "MIST-00001", "category": "DANGEROUS_CALL",
                     "severity": "high", "description": "test", "line": 5}]
        result = _findings_table(findings)
        self.assertIn("<table>", result)
        self.assertIn("Severity", result)

    def test_findings_sorted_by_severity(self):
        findings = [
            {"id": "F1", "severity": "low",      "category": "X", "description": "d", "line": 1},
            {"id": "F2", "severity": "critical",  "category": "X", "description": "d", "line": 2},
            {"id": "F3", "severity": "medium",    "category": "X", "description": "d", "line": 3},
        ]
        result = _findings_table(findings)
        pos_crit = result.index("F2")
        pos_med  = result.index("F3")
        pos_low  = result.index("F1")
        self.assertLess(pos_crit, pos_med)
        self.assertLess(pos_med, pos_low)

    def test_html_escaped_in_description(self):
        findings = [{"id": "F1", "severity": "high",
                     "category": "X",
                     "description": "<script>alert(1)</script>",
                     "line": 1}]
        result = _findings_table(findings)
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;script&gt;", result)


class TestChainsSection(unittest.TestCase):

    def test_empty_chains(self):
        result = _chains_section([])
        self.assertIn("No", result)

    def test_chain_id_present(self):
        chains = [{"id": "CH-0001", "combined_severity": "critical",
                   "narrative": "Test.", "confidence": 0.9, "links": []}]
        result = _chains_section(chains)
        self.assertIn("CH-0001", result)

    def test_chain_narrative_present(self):
        chains = [{"id": "CH-0001", "combined_severity": "high",
                   "narrative": "Exploit path found.", "confidence": 0.8,
                   "links": []}]
        result = _chains_section(chains)
        self.assertIn("Exploit path found.", result)

    def test_confidence_displayed(self):
        chains = [{"id": "CH-0001", "combined_severity": "medium",
                   "narrative": "N.", "confidence": 0.75, "links": []}]
        result = _chains_section(chains)
        self.assertIn("75%", result)


class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.gen    = ReportGenerator(output_dir=self.tmpdir)

    def _make_report(self, source=SAMPLE_SOURCE, risk="high"):
        ir, analysis = make_pipeline(source)
        reasoning    = make_reasoning_stub(risk)
        return self.gen.generate_report(
            ir               = ir,
            analysis_report  = analysis,
            reasoning_result = reasoning,
            target_label     = "test_target.py",
            filename         = "test_report.html"
        )

    def test_report_file_created(self):
        path = self._make_report()
        self.assertTrue(os.path.isfile(path))

    def test_report_is_html(self):
        path = self._make_report()
        with open(path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("<html", content)

    def test_report_has_mistcoder_branding(self):
        path = self._make_report()
        with open(path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("MISTCODER", content)

    def test_report_has_target_name(self):
        path = self._make_report()
        with open(path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("test_target.py", content)

    def test_report_has_risk_rating(self):
        path = self._make_report(risk="critical")
        with open(path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("CRITICAL", content)

    def test_report_has_confidential_banner(self):
        path = self._make_report()
        with open(path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("CONFIDENTIAL", content)

    def test_report_has_findings_section(self):
        path = self._make_report()
        with open(path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("Finding Summary", content)

    def test_report_has_chains_section(self):
        path = self._make_report()
        with open(path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("Vulnerability Chains", content)

    def test_report_has_executive_summary(self):
        path = self._make_report()
        with open(path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("Executive Summary", content)

    def test_report_has_anomalies_section(self):
        path = self._make_report()
        with open(path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("Behavioral Anomalies", content)

    def test_report_has_appendix(self):
        path = self._make_report()
        with open(path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("Technical Appendix", content)

    def test_report_no_raw_script_tags(self):
        ir, analysis = make_pipeline("eval('<script>')\n")
        path = self.gen.generate_report(
            ir=ir, analysis_report=analysis,
            target_label="xss_test.py", filename="xss_test.html"
        )
        with open(path, encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn("<script>alert", content)

    def test_custom_filename(self):
        path = self._make_report()
        self.assertTrue(path.endswith("test_report.html"))

    def test_generate_without_reasoning(self):
        ir, analysis = make_pipeline()
        path = self.gen.generate_report(
            ir=ir, analysis_report=analysis,
            filename="no_reasoning.html"
        )
        self.assertTrue(os.path.isfile(path))

    def test_report_non_empty(self):
        path = self._make_report()
        size = os.path.getsize(path)
        self.assertGreater(size, 4000)

    def test_auto_filename_generated(self):
        ir, analysis = make_pipeline()
        path = self.gen.generate_report(
            ir=ir, analysis_report=analysis,
            target_label="auto_test"
        )
        self.assertTrue(os.path.isfile(path))
        self.assertIn("MISTCODER", os.path.basename(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
