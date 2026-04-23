import tempfile
import pathlib
import unittest

from modules.oversight.src.covenant import Covenant


class TestCovenantCertification(unittest.TestCase):
    def test_certify_scan_adds_chain_record_with_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            chain_file = pathlib.Path(tmp) / "audit_chain.json"
            cov = Covenant(chain_file)

            scan_data = {
                "scan_id": "MSTC-TEST-100",
                "target": "src/app.py",
                "findings": [
                    {"severity": "HIGH", "description": "Hardcoded secret"},
                    {"severity": "MEDIUM", "description": "Weak hashing"},
                ],
                "attack_paths": [{"title": "Path A"}],
            }
            playbook = {
                "name": "finance_mobile_money",
                "playbook_version": "1.0",
                "sector": "finance",
                "system_type": "mobile backend",
            }

            cert = cov.certify_scan(
                scan_data=scan_data,
                playbook=playbook,
                decision="NO-GO",
                tool_version="0.3.0",
                target_hash="abc123",
            )

            self.assertTrue(cert["chain_verified"])
            self.assertEqual(cert["scan_id"], "MSTC-TEST-100")
            self.assertTrue(cert["ledger_hash"])

            last = cov.chain.records[-1]
            self.assertEqual(last.event_type, "SCAN_CERTIFIED")
            self.assertEqual(last.payload["target_identifier"], "src/app.py")
            self.assertEqual(last.payload["target_hash"], "abc123")
            self.assertEqual(last.payload["tool_version"], "0.3.0")
            self.assertEqual(last.payload["playbook"]["name"], "finance_mobile_money")
            self.assertEqual(last.payload["summary_counts"]["total_findings"], 2)
            self.assertEqual(last.payload["decision"], "NO-GO")


if __name__ == "__main__":
    unittest.main(verbosity=2)
