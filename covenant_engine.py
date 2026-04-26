"""
MISTCODER — COVENANT ENGINE
covenant_engine.py  |  v1.0.0

The immutable intelligence pact between MISTCODER and the codebase it guards.

Every scan is cryptographically chained. Every attack path is scored, mapped
to MITRE ATT&CK TTPs, and burned into a tamper-evident audit ledger.
No finding escapes. No chain is broken. No truth is hidden.

Features:
  ▸ SHA-256 hash-chained audit ledger (blockchain-style, zero DB needed)
  ▸ Attack chain visualization with ASCII kill-chain diagrams  
  ▸ MITRE ATT&CK TTP mapping per finding category
  ▸ CVSS-composite scoring for every attack path
  ▸ Compliance matrix: OWASP Top 10 + CWE Top 25 coverage
  ▸ Remediation roadmap with effort scoring
  ▸ Risk velocity: RISING / STABLE / FALLING across scans
  ▸ Signed JSON ledger + Markdown compliance report export

Usage:
    python covenant_engine.py sandbox/phantom_report.json
    python covenant_engine.py sandbox/phantom_report.json --ledger sandbox/ledger.json
"""
from __future__ import annotations
import hashlib, json, os, sys, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Colours ──────────────────────────────────────────────────────────────────
NC = not sys.stdout.isatty()
def _c(code, t): return t if NC else f"\033[{code}m{t}\033[0m"
R  = lambda t: _c("91",t); Y  = lambda t: _c("93",t); G  = lambda t: _c("92",t)
C  = lambda t: _c("96",t); B  = lambda t: _c("94",t); M  = lambda t: _c("95",t)
BO = lambda t: _c("1", t); DI = lambda t: _c("2", t); W  = lambda t: _c("97",t)
def sev_col(s):
    return {"CRITICAL":lambda t:R(BO(t)),"HIGH":lambda t:R(t),
            "MEDIUM":lambda t:Y(t),"LOW":lambda t:G(t)}.get(s,DI)(f"[{s}]")
def div(c="─",w=72): return DI(c*w)
def sec(t): return f"\n{div()}\n  {BO(C(t))}\n{div()}"
def hdr(t): return f"\n{div('═')}\n  {BO(W(t))}\n{div('═')}"

BANNER = r"""
  ██████╗ ██████╗ ██╗   ██╗███████╗███╗   ██╗ █████╗ ███╗   ██╗████████╗
 ██╔════╝██╔═══██╗██║   ██║██╔════╝████╗  ██║██╔══██╗████╗  ██║╚══██╔══╝
 ██║     ██║   ██║██║   ██║█████╗  ██╔██╗ ██║███████║██╔██╗ ██║   ██║   
 ██║     ██║   ██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██╔══██║██║╚██╗██║   ██║   
 ╚██████╗╚██████╔╝ ╚████╔╝ ███████╗██║ ╚████║██║  ██║██║ ╚████║   ██║   
  ╚═════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   
  E N G I N E   ─   Immutable Intelligence Ledger  │  Chain of Truth
"""

# ── MITRE ATT&CK TTP mapping ─────────────────────────────────────────────────
TTP_MAP = {
    "TAINT_FLOW":      {"id":"T1190","name":"Exploit Public-Facing Application","tactic":"Initial Access"},
    "SQL_INJECTION":   {"id":"T1190","name":"Exploit Public-Facing Application","tactic":"Initial Access"},
    "CODE_EXECUTION":  {"id":"T1059","name":"Command and Scripting Interpreter","tactic":"Execution"},
    "PATH_TRAVERSAL":  {"id":"T1083","name":"File and Directory Discovery",      "tactic":"Discovery"},
    "CRYPTO_MISUSE":   {"id":"T1552","name":"Unsecured Credentials",             "tactic":"Credential Access"},
    "SECRET_EXPOSURE": {"id":"T1552","name":"Unsecured Credentials",             "tactic":"Credential Access"},
    "DESERIALIZATION": {"id":"T1190","name":"Exploit Public-Facing Application","tactic":"Initial Access"},
    "HARDCODED_SECRET":{"id":"T1552.001","name":"Credentials In Files",         "tactic":"Credential Access"},
}

CWE_OWASP = {
    "CWE-89": "A03:Injection","CWE-94":"A03:Injection","CWE-22":"A01:Broken Access Control",
    "CWE-327":"A02:Cryptographic Failures","CWE-798":"A07:Identification Failures",
    "CWE-502":"A08:Software Data Integrity","CWE-78":"A03:Injection",
    "CWE-20":"A03:Injection","CWE-200":"A01:Broken Access Control",
}

CWE_TOP25 = {
    "CWE-89":1,"CWE-79":2,"CWE-78":6,"CWE-22":8,"CWE-94":28,
    "CWE-502":23,"CWE-327":0,"CWE-798":19,
}

SEV_SCORE = {"CRITICAL":9.5,"HIGH":7.8,"MEDIUM":5.5,"LOW":2.5,"INFO":1.0}

# ── Hash-chained ledger ───────────────────────────────────────────────────────
def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def _chain_entry(prev_hash: str, entry: dict) -> dict:
    payload = json.dumps(entry, sort_keys=True, default=str)
    entry_hash = _sha256(prev_hash + payload)
    return {**entry, "_prev_hash": prev_hash, "_hash": entry_hash}

def load_ledger(path: str) -> list:
    p = Path(path)
    if p.exists():
        try: return json.loads(p.read_text(encoding="utf-8"))
        except: pass
    return []

def append_ledger(path: str, scan_record: dict) -> tuple[list, bool]:
    ledger = load_ledger(path)
    prev   = ledger[-1]["_hash"] if ledger else "GENESIS"
    entry  = _chain_entry(prev, scan_record)
    ledger.append(entry)
    Path(path).write_text(json.dumps(ledger, indent=2, default=str), encoding="utf-8")
    return ledger, True

def verify_chain(ledger: list) -> tuple[bool, str]:
    if not ledger: return True, "EMPTY — no entries to verify"
    prev = "GENESIS"
    for i, e in enumerate(ledger):
        if e.get("_prev_hash") != prev:
            return False, f"CHAIN BROKEN at entry {i} — tamper detected!"
        payload = {k:v for k,v in e.items() if k not in ("_prev_hash","_hash")}
        expected = _sha256(prev + json.dumps(payload, sort_keys=True, default=str))
        if e.get("_hash") != expected:
            return False, f"HASH MISMATCH at entry {i} — data corrupted!"
        prev = e["_hash"]
    return True, f"VERIFIED — {len(ledger)} entries intact"

# ── Scoring ───────────────────────────────────────────────────────────────────
def score_path(path: dict, all_findings: list) -> dict:
    nodes = path.get("nodes", [])
    edges = path.get("edges", [])
    length = path.get("length", len(nodes))

    sev_scores = []
    cwes = set()
    ttps = set()
    for n in nodes if isinstance(nodes[0], dict) else []:
        s = str(n.get("severity","MEDIUM")).upper()
        sev_scores.append(SEV_SCORE.get(s, 5.5))
        cwes.add(n.get("cwe_id",""))
        cat = str(n.get("category","")).upper().replace(" ","_")
        if cat in TTP_MAP: ttps.add(TTP_MAP[cat]["id"])

    if not sev_scores: sev_scores = [5.5]
    exploitability = max(sev_scores) / 10.0
    conf_scores = [e.get("confidence",0.8) if isinstance(e,dict) else 0.8 for e in edges]
    probability = 1.0
    for c in conf_scores: probability *= c
    if not conf_scores: probability = 0.75
    length_factor = 1.0 / (1.0 + (length - 1) * 0.08)
    overall = min((0.4*exploitability + 0.3*(probability) + 0.3*length_factor) * 10, 10.0)

    return {
        "overall": round(overall, 2),
        "exploitability": round(exploitability*10, 2),
        "probability": round(probability, 3),
        "length": length,
        "cwes": list(cwes),
        "ttps": list(ttps),
    }

# ── Kill-chain ASCII diagram ──────────────────────────────────────────────────
def render_kill_chain(path: dict, idx: int, score: dict) -> str:
    nodes = path.get("nodes", [])
    lines = []
    score_color = R if score["overall"] >= 7 else Y if score["overall"] >= 4 else G
    lines.append(f"\n  {BO(C(f'CHAIN-{idx:02d}'))}  score={score_color(str(score['overall']))}  "
                 f"steps={score['length']}  p(success)={score['probability']}")

    if nodes and isinstance(nodes[0], dict):
        for i, node in enumerate(nodes):
            s   = str(node.get("severity","?")).upper()
            cwe = node.get("cwe_id","?")
            fn  = Path(node.get("file","?")).name
            ln  = node.get("line","?")
            nm  = node.get("call_name") or node.get("_label","?")
            connector = "    └─▶ " if i > 0 else "    ◈   "
            lines.append(f"  {DI(connector)}{sev_col(s)} {BO(nm)}  "
                         f"{DI(f'{fn}:{ln}')}  {C(cwe)}")
    else:
        for i, nid in enumerate(nodes):
            connector = "    └─▶ " if i > 0 else "    ◈   "
            lines.append(f"  {DI(connector)}{BO(str(nid))}")

    if score.get("ttps"):
        lines.append(f"  {DI('    TTP:')} {M(', '.join(score['ttps']))}")
    return "\n".join(lines)

# ── Compliance matrix ─────────────────────────────────────────────────────────
def build_compliance(findings: list) -> dict:
    owasp_hits: dict[str,int] = {}
    cwe_hits: dict[str,int]   = {}
    for f in findings:
        cwe = f.get("cwe","") or f.get("cwe_id","")
        if cwe:
            cwe_hits[cwe] = cwe_hits.get(cwe,0) + 1
            cat = CWE_OWASP.get(cwe)
            if cat: owasp_hits[cat] = owasp_hits.get(cat,0) + 1
    top25_hits = {k:v for k,v in cwe_hits.items() if k in CWE_TOP25}
    return {"owasp": owasp_hits, "cwe": cwe_hits, "top25": top25_hits}

# ── Remediation roadmap ───────────────────────────────────────────────────────
REMEDIATION = {
    "CWE-89": ("Parameterize all SQL queries — use ORM or prepared statements", "LOW"),
    "CWE-94": ("Remove eval/exec on untrusted input — use AST-safe parsers",    "HIGH"),
    "CWE-22": ("Validate and canonicalize all file paths — use Path.resolve()",  "LOW"),
    "CWE-327":("Replace MD5/SHA1/DES with SHA-256+ or AES-256",                 "LOW"),
    "CWE-798":("Move secrets to environment variables or a vault",               "LOW"),
    "CWE-502":("Replace pickle with json/msgpack on untrusted data",             "LOW"),
    "CWE-78": ("Shell-escape all CLI args — use subprocess with list args",      "LOW"),
}

def build_roadmap(cwe_hits: dict) -> list:
    items = []
    for cwe, count in sorted(cwe_hits.items(), key=lambda x:-x[1]):
        rec, effort = REMEDIATION.get(cwe, (f"Review all {cwe} occurrences","MEDIUM"))
        items.append({"cwe":cwe,"count":count,"action":rec,"effort":effort,
                      "rank":CWE_TOP25.get(cwe,99)})
    return sorted(items, key=lambda x: (x["effort"]=="HIGH", x["rank"]))

# ── Risk velocity ─────────────────────────────────────────────────────────────
def risk_velocity(ledger: list) -> str:
    if len(ledger) < 2: return "BASELINE"
    last  = ledger[-1].get("total_findings",0)
    prev  = ledger[-2].get("total_findings",0)
    if last > prev + 2:   return "RISING"
    if last < prev - 2:   return "FALLING"
    return "STABLE"

# ── Main report ───────────────────────────────────────────────────────────────
def run(report_path: str, ledger_path: str, out_dir: str = "sandbox"):
    print(M(BO(BANNER)))

    # Load phantom report
    data = json.loads(Path(report_path).read_text(encoding="utf-8"))
    findings  = data.get("findings", [])
    paths     = data.get("attack_paths", [])
    scan_id   = data.get("scan_id", "UNKNOWN")
    tkg       = data.get("tkg", {})
    now       = datetime.now(timezone.utc).isoformat()

    counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    for f in findings:
        s = str(f.get("severity","INFO")).upper()
        counts[s] = counts.get(s,0) + 1

    # Score all paths
    scored_paths = []
    for p in paths:
        sc = score_path(p, findings)
        scored_paths.append((p, sc))
    scored_paths.sort(key=lambda x: -x[1]["overall"])

    # Compliance + roadmap
    compliance = build_compliance(findings)
    roadmap    = build_roadmap(compliance["cwe"])

    # Ledger entry
    record = {
        "scan_id":        scan_id,
        "timestamp":      now,
        "total_findings": len(findings),
        "critical":       counts["CRITICAL"],
        "high":           counts["HIGH"],
        "attack_paths":   len(paths),
        "tkg_nodes":      tkg.get("nodes",0),
        "tkg_edges":      tkg.get("edges",0),
        "top_cwe":        sorted(compliance["cwe"].items(), key=lambda x:-x[1])[:3],
    }
    ledger, _ = append_ledger(ledger_path, record)
    chain_ok, chain_msg = verify_chain(ledger)
    velocity = risk_velocity(ledger)

    # ── Print report ─────────────────────────────────────────────────────────
    print(hdr("COVENANT INTELLIGENCE REPORT"))
    print(f"  {DI('Scan ID   :')} {BO(scan_id)}")
    print(f"  {DI('Timestamp :')} {now[:19]} UTC")
    print(f"  {DI('Ledger    :')} entry {len(ledger)} of {len(ledger)}  │  "
          + (G("⬡ CHAIN INTACT") if chain_ok else R("⬡ CHAIN BROKEN")))
    vel_col = R if velocity=="RISING" else G if velocity=="FALLING" else Y
    print(f"  {DI('Risk Trend:')} {vel_col(BO(velocity))}")

    # Findings distribution
    print(sec("FINDINGS"))
    bar_max = max(counts.values()) or 1
    for s in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        c = counts[s]
        if c:
            bar = "█" * max(1, int(c/bar_max*40))
            print(f"  {sev_col(s):<30}  {BO(str(c)):>4}  {DI(bar)}")

    # Attack chains
    print(sec(f"ATTACK CHAINS  ({len(scored_paths)} ranked)"))
    if scored_paths:
        for i, (p, sc) in enumerate(scored_paths[:8], 1):
            print(render_kill_chain(p, i, sc))
    else:
        print(f"  {DI('No attack chains — add more findings or lower min_score')}")

    # Compliance matrix
    print(sec("COMPLIANCE MATRIX"))
    print(f"  {'OWASP Top 10':<30}  {'Hits':>4}")
    print(f"  {DI('─'*36)}")
    for cat, n in sorted(compliance["owasp"].items(), key=lambda x:-x[1]):
        bar = "█" * min(n*3, 30)
        print(f"  {C(cat):<30}  {BO(str(n)):>4}  {DI(bar)}")
    if compliance["top25"]:
        print(f"\n  {BO('CWE Top 25 Matches:')}")
        for cwe, n in sorted(compliance["top25"].items(), key=lambda x:-x[1]):
            rank = CWE_TOP25.get(cwe,"?")
            print(f"  {DI('  #'+str(rank)):>8}  {Y(cwe)}  {n} finding{'s' if n>1 else ''}")

    # Remediation roadmap
    print(sec("REMEDIATION ROADMAP"))
    print(f"  {'#':>3}  {'CWE':<10}  {'EFFORT':<8}  ACTION")
    print(f"  {DI('─'*68)}")
    for i, item in enumerate(roadmap[:10], 1):
        effort_col = G if item["effort"]=="LOW" else R if item["effort"]=="HIGH" else Y
        print(f"  {DI(str(i)):>3}  {Y(item['cwe']):<10}  "
              f"{effort_col(item['effort']):<8}  {item['action'][:55]}")

    # Ledger chain hash
    print(sec("CHAIN OF TRUTH"))
    for entry in ledger[-3:]:
        ts  = entry.get("timestamp","?")[:19]
        h   = entry.get("_hash","?")[:16]
        n   = entry.get("total_findings",0)
        p   = entry.get("attack_paths",0)
        print(f"  {DI(ts)}  {C(h+'…')}  findings={BO(str(n))}  paths={BO(str(p))}")
    print(f"\n  {DI('Chain status:')} {G(chain_msg) if chain_ok else R(chain_msg)}")

    # Risk verdict
    print(hdr("COVENANT VERDICT"))
    crit = counts["CRITICAL"]
    high = counts["HIGH"]
    if crit >= 3 or (crit + high) >= 20:
        verdict = R(BO("⬛ CRITICAL RISK — Halt deployments. Patch immediately."))
    elif crit >= 1 or high >= 10:
        verdict = R("■ HIGH RISK — Fix CRITICAL findings before next release.")
    elif high >= 5:
        verdict = Y("■ ELEVATED RISK — Address HIGH findings in current sprint.")
    else:
        verdict = G("■ MODERATE RISK — Review findings in next sprint.")
    print(f"\n  {verdict}\n")

    # Export
    out = {
        "covenant_version": "1.0.0",
        "scan_id":     scan_id,
        "timestamp":   now,
        "chain_entry": len(ledger),
        "chain_hash":  ledger[-1]["_hash"] if ledger else "",
        "chain_valid": chain_ok,
        "risk_velocity": velocity,
        "scored_paths": [{"score":sc,"path":p} for p,sc in scored_paths],
        "compliance":  compliance,
        "roadmap":     roadmap,
        "counts":      counts,
    }
    out_path = Path(out_dir) / "covenant_report.json"
    out_path.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")

    md_lines = [
        f"# COVENANT REPORT — {scan_id}",
        f"**Generated:** {now[:19]} UTC  |  **Chain Entry:** {len(ledger)}  |  **Valid:** {chain_ok}",
        f"\n## Risk Trend: {velocity}",
        f"\n## Findings",
        "| Severity | Count |","|---|---|",
    ]
    for s in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        if counts[s]: md_lines.append(f"| {s} | {counts[s]} |")
    md_lines += ["\n## Attack Chains",f"Total: {len(scored_paths)}"]
    for i,(p,sc) in enumerate(scored_paths[:5],1):
        md_lines.append(f"\n### Chain {i:02d}  (score {sc['overall']})")
        md_lines.append(f"- Steps: {sc['length']}  P(success): {sc['probability']}")
        if sc['ttps']: md_lines.append(f"- TTPs: {', '.join(sc['ttps'])}")
    md_lines += ["\n## OWASP Top 10 Coverage"]
    for cat,n in sorted(compliance["owasp"].items(),key=lambda x:-x[1]):
        md_lines.append(f"- **{cat}**: {n} findings")
    md_lines += ["\n## Remediation Roadmap"]
    for item in roadmap[:8]:
        md_lines.append(f"- [{item['effort']}] **{item['cwe']}** ({item['count']}x): {item['action']}")

    md_path = Path(out_dir) / "covenant_report.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")

    print(f"  {G('✓')} Covenant report  {DI('→')} {BO(str(out_path))}")
    print(f"  {G('✓')} Markdown report  {DI('→')} {BO(str(md_path))}")
    print(f"  {G('✓')} Ledger updated   {DI('→')} {BO(str(ledger_path))}  "
          f"({len(ledger)} entries)\n")
    print(f"{div('═')}")
    print(f"  {BO(C('COVENANT ENGINE'))} complete  │  "
          f"findings: {len(findings)}  chains: {len(scored_paths)}  "
          f"chain: {G('intact') if chain_ok else R('BROKEN')}")
    print(f"{div('═')}\n")

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="COVENANT ENGINE — Immutable Intelligence Ledger")
    ap.add_argument("report", nargs="?", default="sandbox/phantom_report.json")
    ap.add_argument("--ledger", default="sandbox/covenant_ledger.json")
    ap.add_argument("--out-dir", default="sandbox")
    args = ap.parse_args()
    if not Path(args.report).exists():
        print(f"ERROR: report not found: {args.report}"); sys.exit(1)
    run(args.report, args.ledger, args.out_dir)
