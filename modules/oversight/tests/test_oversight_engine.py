"""
MISTCODER -- Oversight Layer (MOD-05)
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

from oversight_engine import (
    AuditLog, PolicyEngine, ApprovalGate, KillSwitch,
    ComplianceExporter, OversightEngine,
    GENESIS_HASH, DEFAULT_POLICY, OWASP_MAP, NIST_MAP, SOC2_MAP, ISO_MAP,
    _get_controls,
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

def make_findings():
    ir     = PythonParser(SAMPLE_SOURCE, "test.py").parse()
    report = AnalysisEngine().analyze(ir)
    return report.get("findings", [])


# ── AuditLog tests ────────────────────────────────────────────────────────────

class TestAuditLog(unittest.TestCase):

    def test_empty_log_verifies(self):
        log    = AuditLog()
        result = log.verify()
        self.assertTrue(result["valid"])
        self.assertEqual(result["entry_count"], 0)

    def test_log_creates_entry(self):
        log   = AuditLog()
        entry = log.log("TEST_ACTION", actor="unit_test")
        self.assertEqual(entry["action"], "TEST_ACTION")
        self.assertEqual(entry["actor"],  "unit_test")

    def test_entry_has_hash(self):
        log   = AuditLog()
        entry = log.log("TEST")
        self.assertIn("hash", entry)
        self.assertEqual(len(entry["hash"]), 64)

    def test_entry_has_hmac(self):
        log   = AuditLog()
        entry = log.log("TEST")
        self.assertIn("hmac", entry)

    def test_first_entry_prev_hash_is_genesis(self):
        log   = AuditLog()
        entry = log.log("TEST")
        self.assertEqual(entry["prev_hash"], GENESIS_HASH)

    def test_chain_links_entries(self):
        log = AuditLog()
        e1  = log.log("ACTION_1")
        e2  = log.log("ACTION_2")
        self.assertEqual(e2["prev_hash"], e1["hash"])

    def test_verify_valid_chain(self):
        log = AuditLog()
        for i in range(5):
            log.log(f"ACTION_{i}")
        result = log.verify()
        self.assertTrue(result["valid"])
        self.assertEqual(result["entry_count"], 5)

    def test_tampered_entry_detected(self):
        log = AuditLog()
        log.log("ACTION_1")
        log.log("ACTION_2")
        log._entries[0]["action"] = "TAMPERED"
        result = log.verify()
        self.assertFalse(result["valid"])
        self.assertGreater(len(result["errors"]), 0)

    def test_export_returns_list(self):
        log = AuditLog()
        log.log("A"); log.log("B")
        exported = log.export()
        self.assertIsInstance(exported, list)
        self.assertEqual(len(exported), 2)

    def test_len_reflects_entry_count(self):
        log = AuditLog()
        log.log("A"); log.log("B"); log.log("C")
        self.assertEqual(len(log), 3)


# ── PolicyEngine tests ────────────────────────────────────────────────────────

class TestPolicyEngine(unittest.TestCase):

    def test_default_low_is_approved(self):
        pe = PolicyEngine()
        self.assertEqual(pe.evaluate("RCE", "LOW"), "APPROVED")

    def test_default_medium_requires_confirmation(self):
        pe = PolicyEngine()
        self.assertEqual(pe.evaluate("RCE", "MEDIUM"), "REQUIRES_CONFIRMATION")

    def test_default_high_requires_confirmation(self):
        pe = PolicyEngine()
        self.assertEqual(pe.evaluate("RCE", "HIGH"), "REQUIRES_CONFIRMATION")

    def test_denied_scenario_type(self):
        pe = PolicyEngine(policy={
            **DEFAULT_POLICY,
            "denied_scenario_types": ["RCE"],
        })
        self.assertEqual(pe.evaluate("RCE", "LOW"), "DENIED")

    def test_max_depth_enforced(self):
        pe = PolicyEngine(policy={**DEFAULT_POLICY, "max_depth": "LOW"})
        self.assertEqual(pe.evaluate("RCE", "HIGH"), "DENIED")

    def test_policy_from_json_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                        delete=False) as f:
            json.dump(DEFAULT_POLICY, f)
            path = f.name
        try:
            pe = PolicyEngine(policy_path=path)
            self.assertEqual(pe.evaluate("RCE", "LOW"), "APPROVED")
        finally:
            os.unlink(path)

    def test_policy_save_and_reload(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "policy.json")
            pe   = PolicyEngine()
            pe.save(path)
            pe2  = PolicyEngine(policy_path=path)
            self.assertEqual(pe2.policy, pe.policy)


# ── ApprovalGate tests ────────────────────────────────────────────────────────

class TestApprovalGate(unittest.TestCase):

    def test_low_depth_auto_approved(self):
        gate   = ApprovalGate()
        result = gate.request("RCE", "LOW")
        self.assertEqual(result["status"], "APPROVED")

    def test_medium_depth_requires_confirmation(self):
        gate   = ApprovalGate()
        result = gate.request("RCE", "MEDIUM")
        self.assertEqual(result["status"], "REQUIRES_CONFIRMATION")

    def test_token_returned(self):
        gate   = ApprovalGate()
        result = gate.request("RCE", "MEDIUM")
        self.assertIn("token", result)
        self.assertTrue(len(result["token"]) > 0)

    def test_confirm_valid_token(self):
        gate    = ApprovalGate()
        request = gate.request("RCE", "MEDIUM")
        confirm = gate.confirm(request["token"], actor="ANALYST")
        self.assertEqual(confirm["status"], "APPROVED")
        self.assertEqual(confirm["confirmed_by"], "ANALYST")

    def test_deny_valid_token(self):
        gate    = ApprovalGate()
        request = gate.request("RCE", "HIGH")
        result  = gate.deny(request["token"], actor="ANALYST")
        self.assertEqual(result["status"], "DENIED")

    def test_confirm_invalid_token(self):
        gate   = ApprovalGate()
        result = gate.confirm("nonexistent_token")
        self.assertEqual(result["status"], "NOT_FOUND")

    def test_pending_count_decrements_on_confirm(self):
        gate = ApprovalGate()
        r    = gate.request("RCE", "MEDIUM")
        self.assertEqual(gate.pending_count, 1)
        gate.confirm(r["token"])
        self.assertEqual(gate.pending_count, 0)

    def test_audit_log_records_request(self):
        log  = AuditLog()
        gate = ApprovalGate(audit_log=log)
        gate.request("RCE", "LOW")
        self.assertGreater(len(log), 0)


# ── KillSwitch tests ──────────────────────────────────────────────────────────

class TestKillSwitch(unittest.TestCase):

    def test_not_engaged_by_default(self):
        ks = KillSwitch()
        self.assertFalse(ks.is_engaged())

    def test_engage_sets_flag(self):
        ks = KillSwitch()
        ks.engage(reason="test")
        self.assertTrue(ks.is_engaged())

    def test_engage_returns_reset_token(self):
        ks     = KillSwitch()
        result = ks.engage()
        self.assertIn("reset_token", result)
        self.assertTrue(len(result["reset_token"]) > 0)

    def test_reset_with_valid_token(self):
        ks     = KillSwitch()
        result = ks.engage()
        reset  = ks.reset(result["reset_token"], actor="HUMAN")
        self.assertTrue(reset["success"])
        self.assertFalse(ks.is_engaged())

    def test_reset_with_invalid_token_fails(self):
        ks = KillSwitch()
        ks.engage()
        reset = ks.reset("wrong_token")
        self.assertFalse(reset["success"])
        self.assertTrue(ks.is_engaged())

    def test_reset_when_not_engaged(self):
        ks    = KillSwitch()
        reset = ks.reset("any_token")
        self.assertFalse(reset["success"])

    def test_engage_logs_to_audit(self):
        log = AuditLog()
        ks  = KillSwitch(audit_log=log)
        ks.engage(reason="test")
        actions = [e["action"] for e in log.export()]
        self.assertIn("KILL_SWITCH_ENGAGED", actions)


# ── ComplianceExporter tests ──────────────────────────────────────────────────

class TestComplianceExporter(unittest.TestCase):

    def setUp(self):
        self.findings  = make_findings()
        self.exporter  = ComplianceExporter()

    def test_export_returns_dict(self):
        result = self.exporter.export(self.findings)
        self.assertIsInstance(result, dict)

    def test_export_has_summary(self):
        result = self.exporter.export(self.findings)
        self.assertIn("summary", result)

    def test_summary_has_framework_keys(self):
        result = self.exporter.export(self.findings)
        s = result["summary"]
        for key in ("owasp_controls_triggered", "nist_controls_triggered",
                    "soc2_controls_triggered", "iso27001_controls_triggered"):
            self.assertIn(key, s)

    def test_finding_count_matches(self):
        result = self.exporter.export(self.findings)
        self.assertEqual(result["summary"]["finding_count"], len(self.findings))

    def test_owasp_controls_non_empty_for_known_category(self):
        controls = _get_controls("DANGEROUS_CALL")
        self.assertGreater(len(controls["owasp"]), 0)
        self.assertNotIn("No direct mapping", controls["owasp"][0])

    def test_unknown_category_returns_default_message(self):
        controls = _get_controls("UNKNOWN_CATEGORY_XYZ")
        self.assertIn("No direct mapping identified.", controls["owasp"])

    def test_export_json_writes_file(self):
        with tempfile.TemporaryDirectory() as d:
            path   = os.path.join(d, "compliance.json")
            result = self.exporter.export_json(self.findings, path, "test")
            self.assertTrue(os.path.isfile(result))
            with open(result, encoding="utf-8") as f:
                data = json.load(f)
            self.assertIn("summary", data)

    def test_all_four_frameworks_present(self):
        result = self.exporter.export(self.findings)
        for fw in ("owasp", "nist", "soc2", "iso27001"):
            self.assertIn(fw, result["frameworks"])


# ── OversightEngine integration tests ────────────────────────────────────────

class TestOversightEngine(unittest.TestCase):

    def setUp(self):
        self.engine   = OversightEngine()
        self.findings = make_findings()

    def test_status_returns_dict(self):
        s = self.engine.status()
        for key in ("kill_switch_engaged", "pending_approvals",
                    "audit_entries", "policy"):
            self.assertIn(key, s)

    def test_low_auto_approved(self):
        result = self.engine.request_approval("RCE", "LOW")
        self.assertEqual(result["status"], "APPROVED")

    def test_medium_requires_confirmation(self):
        result = self.engine.request_approval("RCE", "MEDIUM")
        self.assertEqual(result["status"], "REQUIRES_CONFIRMATION")

    def test_confirm_flow(self):
        req     = self.engine.request_approval("RCE", "MEDIUM")
        confirm = self.engine.confirm(req["token"], actor="ANALYST")
        self.assertEqual(confirm["status"], "APPROVED")

    def test_kill_switch_blocks_all_requests(self):
        self.engine.engage_kill_switch(reason="test", actor="HUMAN")
        result = self.engine.request_approval("RCE", "LOW")
        self.assertEqual(result["status"], "KILLED")

    def test_kill_switch_reset_restores_approvals(self):
        engage = self.engine.engage_kill_switch()
        self.engine.reset_kill_switch(engage["reset_token"])
        result = self.engine.request_approval("RCE", "LOW")
        self.assertEqual(result["status"], "APPROVED")

    def test_audit_log_grows_with_actions(self):
        before = self.engine.status()["audit_entries"]
        self.engine.request_approval("RCE", "LOW")
        self.engine.request_approval("INJECTION", "MEDIUM")
        after = self.engine.status()["audit_entries"]
        self.assertGreater(after, before)

    def test_verify_audit_log_valid(self):
        self.engine.request_approval("RCE", "LOW")
        result = self.engine.verify_audit_log()
        self.assertTrue(result["valid"])

    def test_compliance_export_runs(self):
        result = self.engine.export_compliance(self.findings, "test_target")
        self.assertIn("summary", result)
        self.assertGreater(result["summary"]["finding_count"], 0)

    def test_get_audit_log_returns_list(self):
        log = self.engine.get_audit_log()
        self.assertIsInstance(log, list)


if __name__ == "__main__":
    unittest.main(verbosity=2)
