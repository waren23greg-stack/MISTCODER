import json
import os
import tempfile
import unittest

import mistcoder


class TestAssuranceReporting(unittest.TestCase):
    def test_playbook_loader_supports_defaults(self):
        pb = mistcoder._load_playbook("finance")
        self.assertEqual(pb["sector"], "finance")
        self.assertIn("thresholds", pb)

    def test_executive_report_decision_from_thresholds(self):
        scan_data = {
            "scan_id": "MSTC-EXE-1",
            "target": "demo.py",
            "findings": [{"severity": "HIGH", "description": "Issue A"}],
            "attack_paths": [],
        }
        playbook = {
            "name": "demo",
            "playbook_version": "1.0",
            "sector": "finance",
            "system_type": "API backend",
            "thresholds": {"max_critical": 0, "max_high": 0, "max_medium": 2},
            "impact_narratives": {"default": "Potential business impact."},
            "effort_estimates": {"high": "high"},
        }
        report = mistcoder._build_executive_report(scan_data, playbook)
        self.assertEqual(report["go_no_go"]["decision"], "NO-GO")
        self.assertGreaterEqual(len(report["top_risks"]), 1)

    def test_generate_executive_report_outputs_json_and_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan_path = os.path.join(tmp, "scan.json")
            out_base = os.path.join(tmp, "exec")
            with open(scan_path, "w", encoding="utf-8") as f:
                json.dump({
                    "scan_id": "MSTC-EXE-2",
                    "target": "demo.py",
                    "findings": [{"severity": "MEDIUM", "description": "Issue B"}],
                    "attack_paths": [{"title": "Chain-1", "risk_score": 7.2}],
                }, f)

            out_json, out_html, report = mistcoder.generate_executive_report(
                input_path=scan_path,
                playbook_name="government",
                output_base=out_base,
                auto_certify=False,
            )
            self.assertTrue(os.path.isfile(out_json))
            self.assertTrue(os.path.isfile(out_html))
            self.assertEqual(report["sector"], "government")
            with open(out_html, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Executive Assurance Report", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
