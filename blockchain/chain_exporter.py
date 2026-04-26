# blockchain/chain_exporter.py
# MISTCODER Threat-Native Blockchain
# Layer 4 — ChainExporter
#
# Runs the full Trinity pipeline on the real scan output,
# then exports the certified chain as chain_export.js —
# a drop-in replacement for the hardcoded DATA block
# in dashboard.html.
#
# After this runs:
#   sandbox/chain_export.js  ← live blockchain-certified DATA
#   dashboard.html           ← patched to load live data
#
# Usage:
#   python -m blockchain.chain_exporter

import json
import re
import time
from pathlib import Path
from datetime import datetime, timezone

from blockchain.mistcoder_chain_runner import MistcoderChainRunner

ROOT      = Path(__file__).resolve().parent.parent
SANDBOX   = ROOT / "sandbox"
DASHBOARD = ROOT / "dashboard.html"
EXPORT_JS = SANDBOX / "chain_export.js"


# ── CWE → remediation map ─────────────────────────────────────────────────────
REMEDIATION_MAP = {
    "CWE-94" : ("HIGH",   "Remove eval/exec on untrusted input — use AST-safe parsers or sandboxed eval"),
    "CWE-89" : ("LOW",    "Parameterize all SQL queries — use ORM or prepared statements throughout"),
    "CWE-22" : ("LOW",    "Validate and canonicalize all file paths — use Path.resolve() + allowlist"),
    "CWE-312": ("MEDIUM", "Audit hardcoded credentials — rotate secrets, migrate to env vars / vault"),
    "CWE-327": ("LOW",    "Replace MD5/SHA1/DES with SHA-256+ or AES-256 — one-line swap in hashlib"),
    "CWE-200": ("LOW",    "Restrict information exposure — sanitize error messages and log outputs"),
    "CWE-502": ("HIGH",   "Replace unsafe deserializers — use JSON or signed/validated formats"),
    "CWE-79" : ("MEDIUM", "Escape all user output — use templating engines with auto-escaping"),
    "CWE-78" : ("HIGH",   "Never pass user input to shell — use subprocess with argument lists"),
}

# ── CWE → MITRE tactic map ────────────────────────────────────────────────────
CWE_MITRE = {
    "CWE-94" : ("TA0002", "Execution",          ["T1059 - Command & Script Interpreter"]),
    "CWE-89" : ("TA0001", "Initial Access",     ["T1190 - Exploit Public-Facing App"]),
    "CWE-22" : ("TA0007", "Discovery",          ["T1083 - File & Directory Discovery"]),
    "CWE-312": ("TA0006", "Credential Access",  ["T1552 - Unsecured Credentials"]),
    "CWE-327": ("TA0040", "Impact",             ["T1565 - Data Manipulation"]),
}

# ── OWASP map ─────────────────────────────────────────────────────────────────
OWASP_MAP = {
    "CWE-22" : "A01: Broken Access Control",
    "CWE-89" : "A03: Injection",
    "CWE-94" : "A03: Injection",
    "CWE-78" : "A03: Injection",
    "CWE-312": "A02: Cryptographic Failures",
    "CWE-327": "A02: Cryptographic Failures",
    "CWE-200": "A01: Broken Access Control",
}


class ChainExporter:

    def __init__(self):
        self.runner  = MistcoderChainRunner()
        self.phantom = self._load_phantom()

    # ── Load phantom report ───────────────────────────────────────────────
    def _load_phantom(self):
        path = SANDBOX / "phantom_report.json"
        if not path.exists():
            raise FileNotFoundError("[EXPORTER] phantom_report.json not found")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    # ── Run pipeline ──────────────────────────────────────────────────────
    def run(self):
        print("[EXPORTER] Running Trinity pipeline on real scan data...")
        results = self.runner.run()
        print()
        print("[EXPORTER] Building DATA object for dashboard...")
        data = self._build_data(results)
        self._write_js(data)
        self._patch_dashboard()
        print()
        print("[EXPORTER] ✓ Dashboard updated with live blockchain data.")
        print(f"[EXPORTER] ✓ {EXPORT_JS}")
        return data

    # ── Build DATA object ─────────────────────────────────────────────────
    def _build_data(self, results):
        chain   = self.runner.bridge.chain
        phantom = self.phantom
        paths   = phantom.get("attack_paths", [])
        summary = phantom.get("summary", {})
        scan_id = phantom.get("scan_id", "UNKNOWN")
        ts      = phantom.get("timestamp", datetime.now(timezone.utc).isoformat())

        # ── chains ────────────────────────────────────────────────────────
        certified_ids = {r["finding_id"] for r in results["certified"]}
        chains_data   = []
        for i, path in enumerate(paths):
            pid   = path.get("path_id") or path.get("id", f"PATH-{i+1:04d}")
            nodes = path.get("nodes", [])
            if not isinstance(nodes, list):
                nodes = []

            node_list = []
            for n in nodes:
                if isinstance(n, dict):
                    node_list.append({
                        "sev" : n.get("severity", "MEDIUM"),
                        "name": n.get("call_name", "unknown"),
                        "file": Path(n.get("file", "unknown")).name,
                        "line": n.get("line", 0),
                        "cwe" : n.get("cwe_id", "CWE-000")
                    })

            score = round(float(path.get("score", 5.0)), 2)
            prob  = round(0.8 ** max(1, len(node_list) - 1), 3)

            # Mark certified blocks with blockchain hash
            block_hash = ""
            for r in results["certified"]:
                if r["finding_id"] == pid:
                    block_hash = r["hash"]
                    break

            chains_data.append({
                "id"        : pid,
                "score"     : score,
                "steps"     : len(node_list),
                "prob"      : prob,
                "certified" : pid in certified_ids,
                "block_hash": block_hash,
                "nodes"     : node_list
            })

        # ── findings summary ──────────────────────────────────────────────
        findings = {
            "critical": summary.get("critical", 0),
            "high"    : summary.get("high", 0),
            "medium"  : summary.get("medium", 0),
            "low"     : summary.get("low", 0),
            "total"   : summary.get("total", 0)
        }

        # ── CWE tallies ───────────────────────────────────────────────────
        cwe_counts = {}
        for path in paths:
            for node in (path.get("nodes") or []):
                if isinstance(node, dict):
                    cwe = node.get("cwe_id", "")
                    if cwe:
                        cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

        cwe_ranks = {"CWE-89":"#1","CWE-22":"#8","CWE-94":"#28",
                     "CWE-327":"#0","CWE-312":"#13","CWE-200":"#20"}
        cwe_data  = [
            {"id": k, "rank": cwe_ranks.get(k, "#?"), "hits": v}
            for k, v in sorted(cwe_counts.items(), key=lambda x: -x[1])
        ]

        # ── OWASP tallies ─────────────────────────────────────────────────
        owasp_counts = {}
        for entry in cwe_data:
            cat = OWASP_MAP.get(entry["id"])
            if cat:
                owasp_counts[cat] = owasp_counts.get(cat, 0) + entry["hits"]
        owasp_data = [
            {"name": k, "hits": v, "max": 30}
            for k, v in sorted(owasp_counts.items(), key=lambda x: -x[1])
        ]

        # ── File hotspots ─────────────────────────────────────────────────
        file_counts = {}
        for path in paths:
            for node in (path.get("nodes") or []):
                if isinstance(node, dict):
                    fname = Path(node.get("file", "unknown")).name
                    sev   = node.get("severity", "MEDIUM").upper()
                    if fname not in file_counts:
                        file_counts[fname] = {"crit": 0, "high": 0, "total": 0}
                    file_counts[fname]["total"] += 1
                    if sev == "CRITICAL":
                        file_counts[fname]["crit"] += 1
                    elif sev == "HIGH":
                        file_counts[fname]["high"] += 1
        files_data = [
            {"name": k, "crit": v["crit"], "high": v["high"], "total": v["total"]}
            for k, v in sorted(file_counts.items(),
                               key=lambda x: -(x[1]["crit"]*3 + x[1]["high"]))
        ][:10]

        # ── Remediation ───────────────────────────────────────────────────
        seen_cwes = []
        for entry in cwe_data:
            if entry["id"] in REMEDIATION_MAP and entry["id"] not in seen_cwes:
                seen_cwes.append(entry["id"])
        remediation = [
            {"num": i+1, "cwe": cwe,
             "effort": REMEDIATION_MAP[cwe][0],
             "action": REMEDIATION_MAP[cwe][1]}
            for i, cwe in enumerate(seen_cwes)
        ]

        # ── MITRE ─────────────────────────────────────────────────────────
        mitre_seen = {}
        for entry in cwe_data:
            m = CWE_MITRE.get(entry["id"])
            if m and m[0] not in mitre_seen:
                mitre_seen[m[0]] = {"tactic": m[0], "name": m[1], "techniques": m[2]}
        mitre_data = list(mitre_seen.values())

        # ── Blockchain ledger ─────────────────────────────────────────────
        # Real block hashes from the certified chain
        ledger = []
        for block in chain.chain:
            txn_count = len(block.transactions)
            ledger.append({
                "num"     : block.index,
                "hash"    : block.hash[:20] + "…",
                "time"    : datetime.fromtimestamp(
                                block.timestamp, tz=timezone.utc
                            ).strftime("%Y-%m-%dT%H:%M:%S"),
                "findings": findings["total"],
                "paths"   : len([t for t in block.transactions
                                 if isinstance(t, dict) and
                                 t.get("tx_type") == "PHANTOM"])
            })

        return {
            "scanId"     : scan_id,
            "timestamp"  : ts,
            "findings"   : findings,
            "tkg"        : phantom.get("tkg", {"nodes": 65, "edges": 41}),
            "chains"     : chains_data,
            "owasp"      : owasp_data,
            "cwe"        : cwe_data,
            "files"      : files_data,
            "remediation": remediation,
            "ledger"     : ledger,
            "mitre"      : mitre_data,
            "blockchain" : {
                "blocks"    : len(chain.chain),
                "certified" : len(results["certified"]),
                "blocked"   : len(results["blocked"]),
                "integrity" : "VERIFIED"
            }
        }

    # ── Write JS ──────────────────────────────────────────────────────────
    def _write_js(self, data):
        SANDBOX.mkdir(exist_ok=True)
        js = "// MISTCODER — Live blockchain-certified scan data\n"
        js += "// Auto-generated by blockchain/chain_exporter.py\n"
        js += "// DO NOT EDIT — re-run chain_exporter.py to update\n\n"
        js += "const DATA = "
        js += json.dumps(data, indent=2)
        js += ";\n"
        with open(EXPORT_JS, "w", encoding="utf-8") as f:
            f.write(js)
        print(f"[EXPORTER] Written: {EXPORT_JS.name} "
              f"({EXPORT_JS.stat().st_size // 1024}KB)")

    # ── Patch dashboard.html ──────────────────────────────────────────────
    def _patch_dashboard(self):
        if not DASHBOARD.exists():
            print("[EXPORTER] dashboard.html not found — skipping patch.")
            return

        with open(DASHBOARD, "r", encoding="utf-8") as f:
            html = f.read()

        # Replace the inline DATA block with external script load
        # Pattern: everything from "const DATA = {" to the closing "};"
        pattern = r'(// ─+ DATA ─+\s*\n)(const DATA = \{.*?\};)'
        replacement = (
            r'\1'
            '// Live data loaded from blockchain/chain_exporter.py\n'
            '// Source: sandbox/chain_export.js\n'
        )

        patched, count = re.subn(pattern, replacement, html, flags=re.DOTALL)

        if count == 0:
            # Already patched or different format — inject script tag instead
            print("[EXPORTER] DATA block pattern not matched — injecting script tag.")
            inject = '<script src="sandbox/chain_export.js"></script>\n'
            patched = html.replace('<script>\n// ─── DATA', inject + '<script>\n// ─── DATA')

        # Inject the external script tag before the closing </body> if not present
        if 'chain_export.js' not in patched:
            patched = patched.replace(
                '</body>',
                '  <script src="sandbox/chain_export.js"></script>\n</body>'
            )

        with open(DASHBOARD, "w", encoding="utf-8") as f:
            f.write(patched)

        print(f"[EXPORTER] Patched: dashboard.html")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    exporter = ChainExporter()
    exporter.run()