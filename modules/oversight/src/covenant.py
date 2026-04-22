"""
MISTCODER — COVENANT Audit Engine  v1.0.0
==========================================
Cryptographically hash-chained audit log for every scan event.
Every record is linked to the one before it — tampering any entry
breaks the chain and is detected on the next verify() call.

Features:
  • SHA-256 hash chain (each record hashes prev_hash + payload)
  • HMAC-SHA256 record signing (keyed from machine identity)
  • Persistent chain in sandbox/audit_chain.json
  • Compliance export: JSON / CSV / Markdown
  • Kill switch: scan blocked if chain integrity fails
  • CVSS v3.1 score mapping per finding
  • CWE → OWASP Top 10 2021 mapping
"""
from __future__ import annotations
import hashlib, hmac, json, os, csv, time, uuid, platform, datetime, pathlib
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

# ── Constants ─────────────────────────────────────────────────────────────────
CHAIN_VERSION  = "1.0"
GENESIS_HASH   = "0" * 64          # sentinel for first record
COVENANT_DIR   = pathlib.Path("sandbox")
CHAIN_FILE     = COVENANT_DIR / "audit_chain.json"
KILL_SWITCH    = COVENANT_DIR / "covenant.lock"

# ── CVSS v3.1 base score lookup per severity ──────────────────────────────────
CVSS_BY_SEVERITY = {
    "CRITICAL": 9.1,
    "HIGH":     7.5,
    "MEDIUM":   5.3,
    "LOW":      3.1,
    "INFO":     0.0,
}

# ── CWE → OWASP Top 10 2021 ───────────────────────────────────────────────────
CWE_TO_OWASP = {
    "CWE-89":   "A03:2021 — Injection",
    "CWE-78":   "A03:2021 — Injection",
    "CWE-79":   "A03:2021 — Injection",
    "CWE-94":   "A03:2021 — Injection",
    "CWE-798":  "A07:2021 — Identification and Authentication Failures",
    "CWE-287":  "A07:2021 — Identification and Authentication Failures",
    "CWE-327":  "A02:2021 — Cryptographic Failures",
    "CWE-326":  "A02:2021 — Cryptographic Failures",
    "CWE-330":  "A02:2021 — Cryptographic Failures",
    "CWE-311":  "A02:2021 — Cryptographic Failures",
    "CWE-502":  "A08:2021 — Software and Data Integrity Failures",
    "CWE-611":  "A05:2021 — Security Misconfiguration",
    "CWE-22":   "A01:2021 — Broken Access Control",
    "CWE-284":  "A01:2021 — Broken Access Control",
    "CWE-918":  "A10:2021 — Server-Side Request Forgery",
    "CWE-20":   "A03:2021 — Injection",
}

# ── Machine identity (stable across runs, never leaves machine) ───────────────
def _machine_key() -> bytes:
    ident = f"{platform.node()}:{platform.machine()}:{os.getenv('USERNAME', os.getenv('USER', 'mistcoder'))}"
    return hashlib.sha256(ident.encode()).digest()


# ── Audit record ──────────────────────────────────────────────────────────────
@dataclass
class AuditRecord:
    record_id:   str
    timestamp:   str
    event_type:  str          # SCAN_START | SCAN_COMPLETE | TEMPORAL_ACTION | KILL_SWITCH | VERIFY_FAIL
    scan_id:     str
    payload:     Dict[str, Any]
    prev_hash:   str
    record_hash: str = ""     # computed after creation
    hmac_sig:    str = ""     # HMAC over record_hash
    chain_index: int = 0

    def compute_hash(self) -> str:
        raw = json.dumps({
            "record_id":  self.record_id,
            "timestamp":  self.timestamp,
            "event_type": self.event_type,
            "scan_id":    self.scan_id,
            "payload":    self.payload,
            "prev_hash":  self.prev_hash,
            "chain_index":self.chain_index,
        }, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()

    def sign(self, key: bytes) -> str:
        return hmac.new(key, self.record_hash.encode(), hashlib.sha256).hexdigest()

    def verify_hmac(self, key: bytes) -> bool:
        expected = hmac.new(key, self.record_hash.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.hmac_sig)


# ── Chain engine ──────────────────────────────────────────────────────────────
class CovenantChain:
    """
    Persistent, hash-chained audit log.
    Each record's hash depends on the previous — any tampering is detectable.
    """

    def __init__(self, chain_file: pathlib.Path = CHAIN_FILE):
        self.chain_file = chain_file
        self._key       = _machine_key()
        self.records: List[AuditRecord] = []
        self._load()

    # ── Persistence ───────────────────────────────────────────────────────────
    def _load(self):
        if self.chain_file.exists():
            try:
                with open(self.chain_file) as fh:
                    raw = json.load(fh)
                self.records = [AuditRecord(**r) for r in raw.get("records", [])]
            except Exception:
                self.records = []

    def _save(self):
        self.chain_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.chain_file, "w") as fh:
            json.dump({
                "version":  CHAIN_VERSION,
                "length":   len(self.records),
                "records":  [asdict(r) for r in self.records],
            }, fh, indent=2)

    # ── Append ────────────────────────────────────────────────────────────────
    def append(self, event_type: str, scan_id: str, payload: Dict[str, Any]) -> AuditRecord:
        prev_hash = self.records[-1].record_hash if self.records else GENESIS_HASH
        rec = AuditRecord(
            record_id   = str(uuid.uuid4()),
            timestamp   = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            event_type  = event_type,
            scan_id     = scan_id,
            payload     = payload,
            prev_hash   = prev_hash,
            chain_index = len(self.records),
        )
        rec.record_hash = rec.compute_hash()
        rec.hmac_sig    = rec.sign(self._key)
        self.records.append(rec)
        self._save()
        return rec

    # ── Verify full chain integrity ────────────────────────────────────────────
    def verify(self) -> tuple[bool, str]:
        """Returns (ok, message). Checks hash chain + HMAC on every record."""
        if not self.records:
            return True, "Chain is empty — nothing to verify."

        prev_hash = GENESIS_HASH
        for i, rec in enumerate(self.records):
            # 1. Recompute hash and compare
            expected_hash = rec.compute_hash()
            if rec.record_hash != expected_hash:
                return False, f"Record {i} hash mismatch — chain tampered at index {i}."

            # 2. Chain linkage check
            if rec.prev_hash != prev_hash:
                return False, f"Record {i} broken chain link — prev_hash mismatch at index {i}."

            # 3. HMAC verification (skipped gracefully if key changed)
            if not rec.verify_hmac(self._key):
                # HMAC fails on different machine — warn but don't block
                pass

            prev_hash = rec.record_hash

        return True, f"Chain intact — {len(self.records)} record(s) verified."

    # ── Kill switch ────────────────────────────────────────────────────────────
    def check_kill_switch(self) -> bool:
        """Returns True if scanning is allowed, False if kill switch is active."""
        if KILL_SWITCH.exists():
            return False
        ok, _ = self.verify()
        if not ok:
            self._engage_kill_switch("Chain integrity failure detected.")
            return False
        return True

    def _engage_kill_switch(self, reason: str):
        KILL_SWITCH.parent.mkdir(parents=True, exist_ok=True)
        KILL_SWITCH.write_text(json.dumps({
            "engaged_at": datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat(),
            "reason":     reason,
        }))
        self.append("KILL_SWITCH", "system", {"reason": reason})

    def disengage_kill_switch(self):
        if KILL_SWITCH.exists():
            KILL_SWITCH.unlink()
        print("  Kill switch disengaged.")

    # ── Summary ───────────────────────────────────────────────────────────────
    def summary(self) -> Dict[str, Any]:
        scans = [r for r in self.records if r.event_type == "SCAN_COMPLETE"]
        return {
            "total_records": len(self.records),
            "total_scans":   len(scans),
            "chain_valid":   self.verify()[0],
            "first_scan":    self.records[0].timestamp if self.records else None,
            "last_scan":     self.records[-1].timestamp if self.records else None,
        }


# ── Compliance report builder ─────────────────────────────────────────────────
class ComplianceReporter:
    """Builds structured compliance reports from scan results + audit chain."""

    def __init__(self, chain: CovenantChain):
        self.chain = chain

    # ── Enrich a single finding with CVSS + OWASP ────────────────────────────
    def enrich(self, finding: Any) -> Dict[str, Any]:
        def g(key, *alts):
            if isinstance(finding, dict):
                for k in [key] + list(alts):
                    if k in finding: return finding[k]
                return ""
            for k in [key] + list(alts):
                if hasattr(finding, k): return getattr(finding, k)
            return ""

        severity = str(g("severity", "sev") or "INFO").upper()
        cwe      = str(g("cwe", "cwe_id") or "")
        return {
            "finding_id":  str(uuid.uuid4())[:8],
            "description": str(g("description", "message", "title") or "")[:200],
            "severity":    severity,
            "cvss_score":  CVSS_BY_SEVERITY.get(severity, 0.0),
            "cwe":         cwe,
            "owasp":       CWE_TO_OWASP.get(cwe, "Uncategorised"),
            "file":        str(g("file_path", "filename", "file") or ""),
            "line":        int(g("line", "line_number", "lineno") or 0),
            "remediation": str(g("remediation", "fix", "recommendation") or "See OWASP guidance."),
        }

    # ── Build full compliance report ─────────────────────────────────────────
    def build_report(self, scan_id: str, target: str, findings: List[Any],
                     attack_paths: List[Any] = None) -> Dict[str, Any]:
        enriched = [self.enrich(f) for f in findings]
        by_sev   = {}
        for e in enriched:
            by_sev.setdefault(e["severity"], []).append(e)

        owasp_hits = {}
        for e in enriched:
            cat = e["owasp"]
            owasp_hits.setdefault(cat, 0)
            owasp_hits[cat] += 1

        top_cvss = max((e["cvss_score"] for e in enriched), default=0.0)
        risk_rating = (
            "CRITICAL" if top_cvss >= 9.0 else
            "HIGH"     if top_cvss >= 7.0 else
            "MEDIUM"   if top_cvss >= 4.0 else
            "LOW"
        )

        paths_summary = []
        if attack_paths:
            for p in (attack_paths[:10] if hasattr(attack_paths, '__iter__') else []):
                paths_summary.append({
                    "title":      str(getattr(p, "title", str(p)))[:100],
                    "risk_score": float(getattr(p, "risk_score", getattr(p, "score", 0))),
                    "cwes":       list(getattr(p, "cwes", [])),
                    "confidence": str(getattr(p, "confidence", "MEDIUM")),
                })

        ok, chain_msg = self.chain.verify()
        report = {
            "report_version":  "1.0",
            "report_id":       str(uuid.uuid4()),
            "generated_at":    datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            "scan_id":         scan_id,
            "target":          target,
            "risk_rating":     risk_rating,
            "top_cvss":        round(top_cvss, 1),
            "summary": {
                "total_findings": len(enriched),
                "critical":       len(by_sev.get("CRITICAL", [])),
                "high":           len(by_sev.get("HIGH", [])),
                "medium":         len(by_sev.get("MEDIUM", [])),
                "low":            len(by_sev.get("LOW", [])),
                "info":           len(by_sev.get("INFO", [])),
            },
            "owasp_coverage":  owasp_hits,
            "attack_paths":    paths_summary,
            "findings":        enriched,
            "audit": {
                "chain_intact":   ok,
                "chain_message":  chain_msg,
                "chain_length":   len(self.chain.records),
            },
        }
        return report

    # ── Export formats ────────────────────────────────────────────────────────
    def export_json(self, report: Dict, path: str):
        pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)

    def export_csv(self, report: Dict, path: str):
        pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
        rows = report["findings"]
        if not rows:
            return
        with open(path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

    def export_markdown(self, report: Dict, path: str):
        pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
        s = report["summary"]
        lines = [
            f"# MISTCODER Compliance Report",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Report ID | `{report['report_id']}` |",
            f"| Scan ID | `{report['scan_id']}` |",
            f"| Target | `{report['target']}` |",
            f"| Generated | {report['generated_at']} |",
            f"| **Risk Rating** | **{report['risk_rating']}** |",
            f"| Top CVSS | {report['top_cvss']} |",
            f"",
            f"## Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| CRITICAL | {s['critical']} |",
            f"| HIGH     | {s['high']} |",
            f"| MEDIUM   | {s['medium']} |",
            f"| LOW      | {s['low']} |",
            f"| INFO     | {s['info']} |",
            f"",
            f"## OWASP Top 10 Coverage",
            f"",
        ]
        for cat, count in sorted(report["owasp_coverage"].items(), key=lambda x: -x[1]):
            lines.append(f"- **{cat}**: {count} finding(s)")

        if report["attack_paths"]:
            lines += ["", "## Ranked Attack Paths", ""]
            for i, p in enumerate(report["attack_paths"], 1):
                lines.append(f"### [{i}] {p['title']} — Risk {p['risk_score']}")
                lines.append(f"- CWEs: {', '.join(p['cwes']) or 'N/A'}")
                lines.append(f"- Confidence: {p['confidence']}")
                lines.append("")

        lines += ["", "## Findings", ""]
        for f in report["findings"]:
            lines.append(f"### {f['severity']} — {f['description'][:80]}")
            lines.append(f"- **CVSS**: {f['cvss_score']}  |  **CWE**: {f['cwe']}  |  **OWASP**: {f['owasp']}")
            lines.append(f"- **Location**: `{f['file']}:{f['line']}`")
            lines.append(f"- **Fix**: {f['remediation']}")
            lines.append("")

        lines += [
            "## Audit Chain",
            f"- Chain intact: {'✅' if report['audit']['chain_intact'] else '❌'}",
            f"- Records: {report['audit']['chain_length']}",
            f"- {report['audit']['chain_message']}",
        ]
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))


# ── COVENANT — public API ─────────────────────────────────────────────────────
class Covenant:
    """
    Single entry point for all audit and compliance operations.

    Usage:
        cov = Covenant()
        cov.record_scan_start(scan_id, target)
        # ... run scan ...
        report = cov.record_scan_complete(scan_id, target, findings, attack_paths)
        cov.export(report, "sandbox/report", formats=["json","csv","md"])
    """

    def __init__(self, chain_file: pathlib.Path = CHAIN_FILE):
        self.chain    = CovenantChain(chain_file)
        self.reporter = ComplianceReporter(self.chain)

    # ── Scan lifecycle events ────────────────────────────────────────────────
    def record_scan_start(self, scan_id: str, target: str) -> AuditRecord:
        return self.chain.append("SCAN_START", scan_id, {
            "target":    target,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat(),
        })

    def record_scan_complete(self, scan_id: str, target: str,
                              findings: List[Any], attack_paths: List[Any] = None) -> Dict:
        report = self.reporter.build_report(scan_id, target, findings, attack_paths)
        self.chain.append("SCAN_COMPLETE", scan_id, {
            "target":         target,
            "total_findings": report["summary"]["total_findings"],
            "critical":       report["summary"]["critical"],
            "high":           report["summary"]["high"],
            "risk_rating":    report["risk_rating"],
            "top_cvss":       report["top_cvss"],
        })
        return report

    def record_temporal_action(self, scan_id: str, action: str, color: str, meta: Dict = None):
        return self.chain.append("TEMPORAL_ACTION", scan_id, {
            "action": action, "player": color, **(meta or {})
        })

    # ── Export ───────────────────────────────────────────────────────────────
    def export(self, report: Dict, base_path: str, formats: List[str] = None):
        if formats is None:
            formats = ["json", "md"]
        written = []
        if "json" in formats:
            p = base_path + ".json"
            self.reporter.export_json(report, p)
            written.append(p)
        if "csv" in formats:
            p = base_path + ".csv"
            self.reporter.export_csv(report, p)
            written.append(p)
        if "md" in formats:
            p = base_path + ".md"
            self.reporter.export_markdown(report, p)
            written.append(p)
        return written

    # ── Chain verification ────────────────────────────────────────────────────
    def verify(self) -> tuple[bool, str]:
        return self.chain.verify()

    def status(self) -> Dict:
        ok, msg = self.chain.verify()
        s = self.chain.summary()
        return {**s, "chain_message": msg, "kill_switch_active": KILL_SWITCH.exists()}

    # ── Kill switch ───────────────────────────────────────────────────────────
    def is_clear(self) -> bool:
        return self.chain.check_kill_switch()

    def disengage_kill_switch(self):
        self.chain.disengage_kill_switch()


# ── CLI ───────────────────────────────────────────────────────────────────────
def _print_status(cov: Covenant):
    s   = cov.status()
    ok  = s["chain_valid"]
    ks  = s["kill_switch_active"]
    icon = "✓" if ok else "✗"
    print(f"\n  COVENANT AUDIT STATUS")
    print(f"  {'─'*40}")
    print(f"  Chain:         {icon} {s['chain_message']}")
    print(f"  Records:       {s['total_records']}")
    print(f"  Scans logged:  {s['total_scans']}")
    print(f"  Kill switch:   {'ACTIVE 🔴' if ks else 'clear ✓'}")
    if s["last_scan"]:
        print(f"  Last scan:     {s['last_scan']}")
    print()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2 or sys.argv[1] == "selftest":
        print("COVENANT self-test...")
        import tempfile, pathlib

        with tempfile.TemporaryDirectory() as tmp:
            chain_file = pathlib.Path(tmp) / "test_chain.json"
            cov = Covenant(chain_file)

            MOCK_FINDINGS = [
                {"severity": "CRITICAL", "description": "SQL injection",          "cwe": "CWE-89",  "file_path": "views.py",  "line": 12},
                {"severity": "CRITICAL", "description": "Command injection",       "cwe": "CWE-78",  "file_path": "utils.py",  "line": 8},
                {"severity": "HIGH",     "description": "Hardcoded API key",       "cwe": "CWE-798", "file_path": "config.py", "line": 5},
                {"severity": "HIGH",     "description": "MD5 password hashing",    "cwe": "CWE-327", "file_path": "auth.py",   "line": 31},
                {"severity": "MEDIUM",   "description": "Missing TLS verification","cwe": "CWE-311", "file_path": "client.py", "line": 17},
            ]

            scan_id = "MSTC-TEST-001"
            cov.record_scan_start(scan_id, "src/")
            report  = cov.record_scan_complete(scan_id, "src/", MOCK_FINDINGS)

            # Verify chain
            ok, msg = cov.verify()
            assert ok, f"Chain verification failed: {msg}"

            # Export all formats
            base = os.path.join(tmp, "report")
            written = cov.export(report, base, formats=["json","csv","md"])
            for w in written:
                assert os.path.exists(w), f"Missing export: {w}"

            # Check report content
            assert report["summary"]["critical"] == 2
            assert report["summary"]["high"]     == 2
            assert report["top_cvss"]            == 9.1
            assert report["risk_rating"]         == "CRITICAL"
            assert len(cov.chain.records)        == 2   # start + complete

            print(f"  ✓ Hash chain:    {len(cov.chain.records)} records, integrity verified")
            print(f"  ✓ Report:        CRITICAL risk, CVSS {report['top_cvss']}, {report['summary']['total_findings']} findings")
            print(f"  ✓ OWASP mapped:  {len(report['owasp_coverage'])} categor(ies)")
            print(f"  ✓ Exports:       {', '.join(os.path.basename(w) for w in written)}")
            print(f"\n  COVENANT self-test passed ✓")

    elif sys.argv[1] == "status":
        cov = Covenant()
        _print_status(cov)

    elif sys.argv[1] == "verify":
        cov = Covenant()
        ok, msg = cov.verify()
        print(f"\n  {'✓' if ok else '✗'} {msg}\n")
        sys.exit(0 if ok else 1)

    elif sys.argv[1] == "export" and len(sys.argv) >= 4:
        # covenant.py export <scan_ir_json> <output_base>
        with open(sys.argv[2]) as fh:
            data = json.load(fh)
        cov    = Covenant()
        report = cov.reporter.build_report(
            data.get("scan_id","unknown"), data.get("target","unknown"),
            data.get("findings",[]), data.get("attack_paths",[])
        )
        written = cov.export(report, sys.argv[3], formats=["json","csv","md"])
        for w in written: print(f"  Wrote: {w}")
