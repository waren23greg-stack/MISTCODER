"""
MISTCODER -- Oversight Layer (MOD-05) v0.1.0
Human oversight and governance engine.

Components
----------
AuditLog          -- append-only, SHA-256 hash chain + HMAC tamper-evidence
PolicyEngine      -- JSON policy file drives auto-approval rules
ApprovalGate      -- policy evaluation + confirm() manual override
KillSwitch        -- global halt with authorization token reset
ComplianceExporter-- OWASP Top 10, NIST CSF, SOC2, ISO 27001 mapping
OversightEngine   -- unified MOD-05 entry point
"""

import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional


# ── Constants ─────────────────────────────────────────────────────────────────

GENESIS_HASH = "0" * 64

AUTO_APPROVE_DEPTHS  = {"LOW"}
CONFIRM_DEPTHS       = {"MEDIUM", "HIGH"}

APPROVAL_STATUS = {
    "APPROVED":               "Auto-approved by policy.",
    "REQUIRES_CONFIRMATION":  "Manual confirmation required before proceeding.",
    "DENIED":                 "Denied by policy — action not permitted.",
    "KILLED":                 "Kill switch engaged — all actions halted.",
}

# ── OWASP Top 10 (2021) mapping ───────────────────────────────────────────────

OWASP_MAP = {
    "MISSING_AUTHZ":     ["A01:2021 – Broken Access Control"],
    "PRIVILEGE_ESC":     ["A01:2021 – Broken Access Control"],
    "PATH_TRAVERSAL":    ["A01:2021 – Broken Access Control",
                          "A03:2021 – Injection"],
    "HARDCODED_SECRET":  ["A02:2021 – Cryptographic Failures",
                          "A07:2021 – Identification and Authentication Failures"],
    "MISSING_AUTHN":     ["A02:2021 – Cryptographic Failures",
                          "A07:2021 – Identification and Authentication Failures"],
    "DANGEROUS_CALL":    ["A03:2021 – Injection",
                          "A08:2021 – Software and Data Integrity Failures"],
    "COMMAND_INJECTION": ["A03:2021 – Injection"],
    "SQL_INJECTION":     ["A03:2021 – Injection"],
    "XSS":               ["A03:2021 – Injection"],
    "TAINT_FLOW":        ["A03:2021 – Injection"],
    "INSECURE_DESERIAL": ["A08:2021 – Software and Data Integrity Failures"],
    "EXCEPTION_SWALLOW": ["A09:2021 – Security Logging and Monitoring Failures"],
    "SSRF":              ["A10:2021 – Server-Side Request Forgery"],
    "CODE_EXECUTION":    ["A03:2021 – Injection",
                          "A08:2021 – Software and Data Integrity Failures"],
    "OPEN_REDIRECT":     ["A01:2021 – Broken Access Control"],
}

# ── NIST CSF mapping ──────────────────────────────────────────────────────────

NIST_MAP = {
    "MISSING_AUTHZ":     ["PR.AC-1: Identities and credentials managed",
                          "PR.AC-4: Access permissions managed"],
    "PRIVILEGE_ESC":     ["PR.AC-4: Access permissions managed",
                          "DE.CM-3: Personnel activity monitored"],
    "HARDCODED_SECRET":  ["PR.AC-1: Identities and credentials managed",
                          "PR.DS-5: Protections against data leaks"],
    "DANGEROUS_CALL":    ["PR.PT-3: Principle of least functionality",
                          "DE.CM-4: Malicious code detected"],
    "COMMAND_INJECTION": ["PR.PT-3: Principle of least functionality",
                          "DE.CM-4: Malicious code detected"],
    "SQL_INJECTION":     ["PR.DS-1: Data-at-rest protected",
                          "DE.CM-4: Malicious code detected"],
    "XSS":               ["PR.PT-3: Principle of least functionality"],
    "TAINT_FLOW":        ["PR.DS-5: Protections against data leaks"],
    "INSECURE_DESERIAL": ["PR.PT-3: Principle of least functionality",
                          "DE.CM-4: Malicious code detected"],
    "EXCEPTION_SWALLOW": ["DE.AE-3: Event data aggregated and correlated",
                          "RS.AN-1: Notifications from detection systems investigated"],
    "SSRF":              ["PR.AC-5: Network integrity protected",
                          "DE.CM-1: Network monitored"],
    "PATH_TRAVERSAL":    ["PR.DS-5: Protections against data leaks",
                          "PR.AC-4: Access permissions managed"],
    "MISSING_AUTHN":     ["PR.AC-1: Identities and credentials managed"],
}

# ── SOC2 Trust Service Criteria mapping ──────────────────────────────────────

SOC2_MAP = {
    "MISSING_AUTHZ":     ["CC6.1: Logical access security measures",
                          "CC6.3: Role-based access control"],
    "PRIVILEGE_ESC":     ["CC6.1: Logical access security measures",
                          "CC6.6: Unauthorized access prevention"],
    "HARDCODED_SECRET":  ["CC6.1: Logical access security measures",
                          "CC6.7: Transmission and disclosure controls"],
    "DANGEROUS_CALL":    ["CC7.1: System configuration monitored",
                          "CC8.1: Change management process"],
    "COMMAND_INJECTION": ["CC7.1: System configuration monitored"],
    "SQL_INJECTION":     ["CC9.1: Risk mitigation activities",
                          "CC6.7: Transmission and disclosure controls"],
    "XSS":               ["CC9.1: Risk mitigation activities"],
    "TAINT_FLOW":        ["CC6.7: Transmission and disclosure controls"],
    "INSECURE_DESERIAL": ["CC7.1: System configuration monitored",
                          "CC8.1: Change management process"],
    "EXCEPTION_SWALLOW": ["CC7.2: Anomaly and security event monitoring"],
    "SSRF":              ["CC6.6: Unauthorized access prevention",
                          "A1.2: Availability — environmental protections"],
    "PATH_TRAVERSAL":    ["CC6.1: Logical access security measures"],
    "MISSING_AUTHN":     ["CC6.2: Authentication mechanisms"],
}

# ── ISO 27001 Annex A mapping ─────────────────────────────────────────────────

ISO_MAP = {
    "MISSING_AUTHZ":     ["A.9.4.1: Information access restriction",
                          "A.9.2.3: Management of privileged access rights"],
    "PRIVILEGE_ESC":     ["A.9.2.3: Management of privileged access rights",
                          "A.9.4.5: Access control to program source code"],
    "HARDCODED_SECRET":  ["A.10.1.1: Policy on the use of cryptographic controls",
                          "A.9.2.1: User registration and de-registration"],
    "DANGEROUS_CALL":    ["A.14.2.1: Secure development policy",
                          "A.12.6.1: Management of technical vulnerabilities"],
    "COMMAND_INJECTION": ["A.14.2.5: Secure system engineering principles",
                          "A.12.6.1: Management of technical vulnerabilities"],
    "SQL_INJECTION":     ["A.14.2.5: Secure system engineering principles",
                          "A.18.1.3: Protection of records"],
    "XSS":               ["A.14.2.5: Secure system engineering principles"],
    "TAINT_FLOW":        ["A.14.2.1: Secure development policy"],
    "INSECURE_DESERIAL": ["A.14.2.1: Secure development policy",
                          "A.12.5.1: Installation of software on operational systems"],
    "EXCEPTION_SWALLOW": ["A.16.1.2: Reporting information security events",
                          "A.12.4.1: Event logging"],
    "SSRF":              ["A.13.1.3: Segregation in networks",
                          "A.9.4.2: Secure log-on procedures"],
    "PATH_TRAVERSAL":    ["A.9.4.1: Information access restriction"],
    "MISSING_AUTHN":     ["A.9.4.2: Secure log-on procedures",
                          "A.9.2.1: User registration and de-registration"],
}

DEFAULT_POLICY = {
    "auto_approve_depths":   ["LOW"],
    "confirm_depths":        ["MEDIUM", "HIGH"],
    "denied_scenario_types": [],
    "max_depth":             "HIGH",
    "notes":                 "Default MISTCODER oversight policy.",
}


# ── AuditLog ──────────────────────────────────────────────────────────────────

class AuditLog:
    """
    Append-only audit log.
    Each entry carries:
      - SHA-256 of the previous entry's hash (chain integrity)
      - HMAC-SHA256 of the entry content (signing)
    """

    def __init__(self, hmac_key: Optional[str] = None):
        self._key    = (hmac_key or secrets.token_hex(32)).encode()
        self._entries: list = []
        self._prev_hash     = GENESIS_HASH

    def log(self, action: str, actor: str = "MISTCODER",
            data: Optional[dict] = None) -> dict:
        entry = {
            "entry_id":   str(uuid.uuid4()),
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "action":     action,
            "actor":      actor,
            "data":       data or {},
            "prev_hash":  self._prev_hash,
        }
        content      = json.dumps(entry, sort_keys=True).encode()
        entry_hash   = hashlib.sha256(content).hexdigest()
        entry_hmac   = hmac.new(self._key, content, hashlib.sha256).hexdigest()
        entry["hash"] = entry_hash
        entry["hmac"] = entry_hmac
        self._prev_hash = entry_hash
        self._entries.append(entry)
        return entry

    def verify(self) -> dict:
        """Verify full chain integrity. Returns report dict."""
        errors   = []
        prev     = GENESIS_HASH
        for i, entry in enumerate(self._entries):
            stored_hash = entry.get("hash", "")
            stored_hmac = entry.get("hmac", "")
            if entry.get("prev_hash") != prev:
                errors.append(f"Entry {i}: prev_hash mismatch")
            check = {k: v for k, v in entry.items()
                     if k not in ("hash", "hmac")}
            content      = json.dumps(check, sort_keys=True).encode()
            expected_h   = hashlib.sha256(content).hexdigest()
            expected_mac = hmac.new(self._key, content, hashlib.sha256).hexdigest()
            if stored_hash != expected_h:
                errors.append(f"Entry {i}: hash tampered")
            if not hmac.compare_digest(stored_hmac, expected_mac):
                errors.append(f"Entry {i}: HMAC invalid")
            prev = stored_hash
        return {
            "valid":        len(errors) == 0,
            "entry_count":  len(self._entries),
            "errors":       errors,
        }

    def export(self) -> list:
        return list(self._entries)

    def __len__(self):
        return len(self._entries)


# ── PolicyEngine ──────────────────────────────────────────────────────────────

class PolicyEngine:
    """Loads a JSON policy and evaluates approval decisions."""

    def __init__(self, policy: Optional[dict] = None,
                 policy_path: Optional[str] = None):
        if policy_path and os.path.isfile(policy_path):
            with open(policy_path, "r", encoding="utf-8") as f:
                self._policy = json.load(f)
        else:
            self._policy = policy or DEFAULT_POLICY

    def evaluate(self, scenario_type: str, depth: str,
                 severity: str = "medium") -> str:
        """
        Returns one of:
          APPROVED | REQUIRES_CONFIRMATION | DENIED | KILLED
        """
        denied_types = self._policy.get("denied_scenario_types", [])
        if scenario_type in denied_types:
            return "DENIED"

        max_depth = self._policy.get("max_depth", "HIGH")
        depth_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
        if depth_order.get(depth, 0) > depth_order.get(max_depth, 2):
            return "DENIED"

        auto_depths    = self._policy.get("auto_approve_depths", ["LOW"])
        confirm_depths = self._policy.get("confirm_depths", ["MEDIUM", "HIGH"])

        if depth in auto_depths:
            return "APPROVED"
        if depth in confirm_depths:
            return "REQUIRES_CONFIRMATION"
        return "DENIED"

    @property
    def policy(self) -> dict:
        return dict(self._policy)

    def save(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._policy, f, indent=2)


# ── ApprovalGate ──────────────────────────────────────────────────────────────

class ApprovalGate:
    """
    Wraps PolicyEngine.
    Pending actions tracked by token.
    confirm(token) / deny(token) for manual override.
    """

    def __init__(self, policy_engine: Optional[PolicyEngine] = None,
                 audit_log: Optional[AuditLog] = None):
        self._policy  = policy_engine or PolicyEngine()
        self._log     = audit_log if audit_log is not None else AuditLog()
        self._pending: dict = {}

    def request(self, scenario_type: str, depth: str,
                severity: str = "medium",
                actor: str = "MISTCODER") -> dict:
        """
        Evaluate a scenario against policy.
        Returns approval result with token for pending items.
        """
        status = self._policy.evaluate(scenario_type, depth, severity)
        token  = secrets.token_hex(16)
        result = {
            "token":         token,
            "status":        status,
            "status_label":  APPROVAL_STATUS.get(status, status),
            "scenario_type": scenario_type,
            "depth":         depth,
            "severity":      severity,
        }
        if status == "REQUIRES_CONFIRMATION":
            self._pending[token] = result
        self._log.log(
            action=f"APPROVAL_REQUEST:{status}",
            actor=actor,
            data={"scenario_type": scenario_type, "depth": depth,
                  "severity": severity, "token": token},
        )
        return result

    def confirm(self, token: str, actor: str = "HUMAN") -> dict:
        """Manually confirm a pending action."""
        pending = self._pending.pop(token, None)
        if not pending:
            result = {"token": token, "status": "NOT_FOUND",
                      "status_label": "Token not found or already resolved."}
        else:
            result = {**pending, "status": "APPROVED",
                      "status_label": APPROVAL_STATUS["APPROVED"],
                      "confirmed_by": actor}
        self._log.log("MANUAL_CONFIRM", actor=actor,
                      data={"token": token, "outcome": result["status"]})
        return result

    def deny(self, token: str, actor: str = "HUMAN") -> dict:
        """Manually deny a pending action."""
        pending = self._pending.pop(token, None)
        if not pending:
            result = {"token": token, "status": "NOT_FOUND",
                      "status_label": "Token not found or already resolved."}
        else:
            result = {**pending, "status": "DENIED",
                      "status_label": APPROVAL_STATUS["DENIED"],
                      "denied_by": actor}
        self._log.log("MANUAL_DENY", actor=actor,
                      data={"token": token, "outcome": result["status"]})
        return result

    @property
    def pending_count(self) -> int:
        return len(self._pending)


# ── KillSwitch ────────────────────────────────────────────────────────────────

class KillSwitch:
    """
    Global halt mechanism.
    engage()         -- immediately halt all operations
    is_engaged()     -- check current state
    reset(token)     -- re-enable with authorization token
    """

    def __init__(self, audit_log: Optional[AuditLog] = None):
        self._engaged      = False
        self._reset_token: Optional[str] = None
        self._log          = audit_log if audit_log is not None else AuditLog()

    def engage(self, actor: str = "MISTCODER", reason: str = "") -> dict:
        self._engaged     = True
        self._reset_token = secrets.token_hex(32)
        self._log.log("KILL_SWITCH_ENGAGED", actor=actor,
                      data={"reason": reason, "reset_token": self._reset_token})
        return {
            "engaged":     True,
            "reset_token": self._reset_token,
            "actor":       actor,
            "reason":      reason,
        }

    def is_engaged(self) -> bool:
        return self._engaged

    def reset(self, token: str, actor: str = "HUMAN") -> dict:
        if not self._engaged:
            return {"success": False, "reason": "Kill switch is not engaged."}
        if not self._reset_token:
            return {"success": False, "reason": "No reset token available."}
        if not hmac.compare_digest(token, self._reset_token):
            self._log.log("KILL_SWITCH_RESET_FAILED", actor=actor,
                          data={"reason": "Invalid token"})
            return {"success": False, "reason": "Invalid reset token."}
        self._engaged     = False
        self._reset_token = None
        self._log.log("KILL_SWITCH_RESET", actor=actor, data={})
        return {"success": True, "actor": actor}


# ── ComplianceExporter ────────────────────────────────────────────────────────

def _get_controls(category: str) -> dict:
    return {
        "owasp":  OWASP_MAP.get(category, ["No direct mapping identified."]),
        "nist":   NIST_MAP.get(category,  ["No direct mapping identified."]),
        "soc2":   SOC2_MAP.get(category,  ["No direct mapping identified."]),
        "iso27001": ISO_MAP.get(category, ["No direct mapping identified."]),
    }


class ComplianceExporter:
    """
    Maps findings to OWASP Top 10, NIST CSF, SOC2, ISO 27001.
    """

    def export(self, findings: list,
               target: str = "Unknown Target") -> dict:
        mapped    = []
        owasp_set = set()
        nist_set  = set()
        soc2_set  = set()
        iso_set   = set()

        for f in findings:
            cat      = f.get("category", "UNKNOWN")
            controls = _get_controls(cat)
            owasp_set.update(controls["owasp"])
            nist_set.update(controls["nist"])
            soc2_set.update(controls["soc2"])
            iso_set.update(controls["iso27001"])
            mapped.append({
                "finding_id":  f.get("id", "--"),
                "category":    cat,
                "severity":    f.get("severity", "--"),
                "description": f.get("description", "--"),
                "controls":    controls,
            })

        return {
            "target":    target,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "finding_count": len(findings),
                "owasp_controls_triggered":   sorted(owasp_set),
                "nist_controls_triggered":    sorted(nist_set),
                "soc2_controls_triggered":    sorted(soc2_set),
                "iso27001_controls_triggered": sorted(iso_set),
            },
            "findings": mapped,
            "frameworks": {
                "owasp":    "OWASP Top 10 2021",
                "nist":     "NIST Cybersecurity Framework v1.1",
                "soc2":     "SOC2 Trust Service Criteria 2017",
                "iso27001": "ISO/IEC 27001:2013 Annex A",
            },
        }

    def export_json(self, findings: list, output_path: str,
                    target: str = "Unknown Target") -> str:
        report = self.export(findings, target)
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[MOD-05] Compliance report written: {output_path}")
        return output_path


# ── OversightEngine ───────────────────────────────────────────────────────────

class OversightEngine:
    """
    MOD-05 unified entry point.
    Wires AuditLog, PolicyEngine, ApprovalGate,
    KillSwitch, and ComplianceExporter together.
    """

    def __init__(self, hmac_key: Optional[str] = None,
                 policy: Optional[dict] = None,
                 policy_path: Optional[str] = None):
        self.audit      = AuditLog(hmac_key=hmac_key)
        self.policy     = PolicyEngine(policy=policy, policy_path=policy_path)
        self.gate       = ApprovalGate(self.policy, self.audit)
        self.kill       = KillSwitch(self.audit)
        self.compliance = ComplianceExporter()
        self.audit.log("OVERSIGHT_ENGINE_INIT", actor="MISTCODER")

    def request_approval(self, scenario_type: str, depth: str,
                         severity: str = "medium") -> dict:
        if self.kill.is_engaged():
            return {"status": "KILLED",
                    "status_label": APPROVAL_STATUS["KILLED"]}
        return self.gate.request(scenario_type, depth, severity)

    def confirm(self, token: str, actor: str = "HUMAN") -> dict:
        return self.gate.confirm(token, actor)

    def deny(self, token: str, actor: str = "HUMAN") -> dict:
        return self.gate.deny(token, actor)

    def engage_kill_switch(self, reason: str = "", actor: str = "HUMAN") -> dict:
        result = self.kill.engage(actor=actor, reason=reason)
        print(f"[MOD-05] KILL SWITCH ENGAGED by {actor}. "
              f"Reset token: {result['reset_token']}")
        return result

    def reset_kill_switch(self, token: str, actor: str = "HUMAN") -> dict:
        return self.kill.reset(token, actor)

    def export_compliance(self, findings: list,
                          target: str = "Unknown Target",
                          output_path: Optional[str] = None) -> dict:
        report = self.compliance.export(findings, target)
        self.audit.log("COMPLIANCE_EXPORT", data={
            "target":          target,
            "finding_count":   len(findings),
            "frameworks":      list(report["frameworks"].keys()),
        })
        if output_path:
            self.compliance.export_json(findings, output_path, target)
        return report

    def verify_audit_log(self) -> dict:
        return self.audit.verify()

    def get_audit_log(self) -> list:
        return self.audit.export()

    def status(self) -> dict:
        return {
            "kill_switch_engaged": self.kill.is_engaged(),
            "pending_approvals":   self.gate.pending_count,
            "audit_entries":       len(self.audit),
            "policy":              self.policy.policy,
        }
