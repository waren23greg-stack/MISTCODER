#!/usr/bin/env python3
"""
MISTCODER — NEXUS Unified Intelligence CLI  v0.3.0
Fixes: IR_BRIDGE path detection + directory scan routing + PHANTOM integration
"""
import sys, os, json, time, hashlib, datetime, pathlib, html, ast
from typing import Any, Dict, Optional

ROOT = pathlib.Path(__file__).parent
sys.path.insert(0, str(ROOT))

# COVENANT audit engine
try:
    from modules.oversight.src.covenant import Covenant as _CovenantCls
    _COVENANT = _CovenantCls()
except Exception:
    _COVENANT = None

BANNER = r"""
███╗   ███╗██╗███████╗████████╗ ██████╗ ██████╗ ██████╗ ███████╗██████╗
████╗ ████║██║██╔════╝╚══██╔══╝██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗
██╔████╔██║██║███████╗   ██║   ██║     ██║   ██║██║  ██║█████╗  ██████╔╝
██║╚██╔╝██║██║╚════██║   ██║   ██║     ██║   ██║██║  ██║██╔══╝  ██╔══██╗
██║ ╚═╝ ██║██║███████║   ██║   ╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║
╚═╝     ╚═╝╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
  NEXUS — Unified Intelligence CLI  │  All engines, one report
"""

SEP = "─" * 72
MISTCODER_VERSION = "0.3.0"
PLAYBOOK_DIR = ROOT / "playbooks"
DEFAULT_PLAYBOOKS = {
    "finance": "finance_mobile_money.yml",
    "government": "gov_citizen_portal.yml",
    "education": "education_school_portal.yml",
    "health": "health_clinic_system.yml",
}

# ── Module probe — checks all known locations ─────────────────────────────────
def _probe(module_id):
    """Try multiple import paths for each module. Returns (ok, obj_or_None)."""
    probes = {
        "ORACLE": [
            ("modules.ingestion.src.python_ast_walker", "OracleWalker"),
        ],
        "PARSER": [
            ("modules.ingestion.src.mistcoder_parser", "MistcoderParser"),
            ("modules.ingestion.src.parser",           "LanguageParser"),
        ],
        "URL_SCANNER": [
            ("modules.ingestion.src.url_scanner", "URLScanner"),
        ],
        "BINARY_LIFT": [
            ("modules.binary_lifting.src.enhanced_binary_parser", "EnhancedBinaryParser"),
            ("modules.binary_lifting.src.binary_lifting",         "BinaryLifter"),
        ],
        "IR_BRIDGE": [
            ("modules.ingestion.src.ir_bridge",   "IRBridge"),
            ("ir_bridge",                          "IRBridge"),         # repo root fallback
            ("modules.ingestion.ir_bridge",        "IRBridge"),
        ],
        "TKG_BUILDER": [
            ("modules.knowledge_graph.src.threat_kg_builder", "ThreatKGBuilder"),
        ],
        "ATTACK_FINDER": [
            ("modules.knowledge_graph.src.attack_path_finder", "AttackPathFinder"),
        ],
        "REASONING": [
            ("modules.reasoning.src.attack_path_reasoning", "AttackPathReasoner"),
        ],
        "EXPLAINABILITY": [
            ("modules.reasoning.src.explainability_chains", "ExplainabilityChain"),
        ],
    }
    for mod_path, cls_name in probes.get(module_id, []):
        try:
            mod = __import__(mod_path, fromlist=[cls_name])
            return True, getattr(mod, cls_name, None)
        except Exception:
            continue
    return False, None


def get_module_status():
    layers = {
        "Layer 1 — Ingestion":    ["ORACLE", "PARSER", "URL_SCANNER", "BINARY_LIFT"],
        "Layer 2 — Bridge":       ["IR_BRIDGE"],
        "Layer 3 — Knowledge":    ["TKG_BUILDER", "ATTACK_FINDER"],
        "Layer 4 — Reasoning":    ["REASONING", "EXPLAINABILITY"],
    }
    status = {}
    for layer, mods in layers.items():
        for m in mods:
            ok, _ = _probe(m)
            status[m] = ok
    return layers, status


# ── File collection ───────────────────────────────────────────────────────────
def collect_files(target: str):
    """Walk a path, return dict of extension → [filepath]"""
    p = pathlib.Path(target)
    files = {"py": [], "js": [], "ts": [], "binary": [], "url": []}

    if p.is_file():
        ext = p.suffix.lstrip(".")
        if ext in files:
            files[ext].append(str(p))
        return files

    if p.is_dir():
        for f in p.rglob("*"):
            if not f.is_file():
                continue
            # Skip __pycache__ and .git
            parts = f.parts
            if "__pycache__" in parts or ".git" in parts:
                continue
            ext = f.suffix.lstrip(".")
            if ext in files:
                files[ext].append(str(f))
        return files

    # URL target
    if target.startswith("http://") or target.startswith("https://"):
        files["url"].append(target)

    return files


def _arg_value(args, flag, default=None):
    if flag in args:
        idx = args.index(flag)
        if idx + 1 < len(args):
            return args[idx + 1]
    return default


def _resolve_playbook_path(playbook: Optional[str]) -> pathlib.Path:
    if not playbook:
        return PLAYBOOK_DIR / DEFAULT_PLAYBOOKS["finance"]

    token = str(playbook).strip().lower()
    if token in DEFAULT_PLAYBOOKS:
        return PLAYBOOK_DIR / DEFAULT_PLAYBOOKS[token]

    p = pathlib.Path(playbook)
    if p.exists():
        return p
    if not p.is_absolute():
        repo_local = ROOT / playbook
        if repo_local.exists():
            return repo_local

    if not p.suffix:
        candidate = PLAYBOOK_DIR / f"{playbook}.yml"
        if candidate.exists():
            return candidate

    raise FileNotFoundError(f"Playbook not found: {playbook}")


def _load_playbook(playbook: Optional[str] = None) -> Dict[str, Any]:
    p = _resolve_playbook_path(playbook)
    raw = p.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except Exception:
        try:
            import yaml  # type: ignore
            data = yaml.safe_load(raw)
        except Exception as e:
            raise ValueError(f"Unable to parse playbook {p}. Use JSON-compatible YAML. ({e})")

    if not isinstance(data, dict):
        raise ValueError(f"Invalid playbook structure in {p}")

    data.setdefault("name", p.stem)
    data.setdefault("playbook_version", "1.0")
    data.setdefault("sector", "finance")
    data.setdefault("system_type", "web portal")
    data.setdefault("risk_priorities", [])
    data.setdefault("thresholds", {"max_critical": 0, "max_high": 0, "max_medium": 2})
    data.setdefault("reporting", {"executive": "plain_language", "technical": "full"})
    data.setdefault("impact_narratives", {})
    data.setdefault("effort_estimates", {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "low"})
    data["_path"] = str(p)
    return data


def _finding_dict(f):
    if isinstance(f, dict):
        return f
    if isinstance(f, str):
        s = f.strip()
        if s.startswith("{") and s.endswith("}"):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
            try:
                parsed = ast.literal_eval(s)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
        return {"description": s}
    if hasattr(f, "__dict__"):
        return dict(f.__dict__)
    return {"description": str(f)}


def _findings_summary(findings):
    summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        level = str(_finding_dict(f).get("severity", "info")).strip().lower()
        if level not in summary:
            level = "info"
        summary[level] += 1
    return summary


def _decision_from_playbook(findings_summary, playbook):
    t = playbook.get("thresholds", {}) or {}
    checks = [("critical", "max_critical"), ("high", "max_high"), ("medium", "max_medium")]
    failures = []
    for sev, key in checks:
        max_allowed = t.get(key, 999999)
        try:
            max_allowed = int(max_allowed)
        except Exception:
            max_allowed = 999999
        if findings_summary.get(sev, 0) > max_allowed:
            failures.append(f"{sev.upper()} findings {findings_summary.get(sev, 0)} > {max_allowed}")
    return ("NO-GO", failures) if failures else ("GO", [])


def _impact_narrative(finding, playbook):
    f = _finding_dict(finding)
    impacts = playbook.get("impact_narratives", {}) or {}
    sev = str(f.get("severity", "INFO")).upper()
    category = str(f.get("category", "")).upper()
    cwe = str(f.get("cwe", "")).upper()
    by_sev = (impacts.get("severity", {}) or {}).get(sev)
    by_cat = (impacts.get("categories", {}) or {}).get(category)
    by_cwe = (impacts.get("cwe", {}) or {}).get(cwe)
    return by_cat or by_cwe or by_sev or impacts.get("default", "Could expose sensitive operations, data, or service continuity.")


def _effort_for_finding(finding, playbook):
    sev = str(_finding_dict(finding).get("severity", "info")).strip().lower()
    return (playbook.get("effort_estimates", {}) or {}).get(sev, "medium")


def _severity_rank(value):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(str(value).lower(), 4)


def _compute_target_hash(target: str) -> Optional[str]:
    if not target:
        return None
    if target.startswith("http://") or target.startswith("https://"):
        return None
    p = pathlib.Path(target)
    if p.is_file():
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    if p.is_dir():
        h = hashlib.sha256()
        for f in sorted(x for x in p.rglob("*") if x.is_file()):
            try:
                rel = str(f.relative_to(p))
            except Exception:
                rel = str(f)
            h.update(rel.encode())
            with open(f, "rb") as fh:
                while True:
                    chunk = fh.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
        return h.hexdigest()
    return None


def _build_executive_report(scan_data: Dict[str, Any], playbook: Dict[str, Any], audit_ref: Dict[str, Any] = None) -> Dict[str, Any]:
    findings = scan_data.get("findings", []) or []
    attack_paths = scan_data.get("attack_paths", []) or []
    summary = _findings_summary(findings)
    decision, failure_reasons = _decision_from_playbook(summary, playbook)

    top_findings = sorted((_finding_dict(f) for f in findings), key=lambda f: _severity_rank(f.get("severity")))[:5]
    top_risks = []
    for f in top_findings:
        top_risks.append({
            "severity": str(f.get("severity", "INFO")).upper(),
            "issue": str(f.get("description") or f.get("message") or f.get("category") or "Security issue"),
            "impact": _impact_narrative(f, playbook),
            "effort_estimate": _effort_for_finding(f, playbook),
            "location": f"{f.get('file_path') or f.get('filename') or ''}:{f.get('line') or f.get('line_number') or ''}".strip(":"),
        })

    scenarios = []
    for i, p in enumerate(attack_paths[:3], 1):
        pd = _finding_dict(p)
        title = pd.get("title") or pd.get("name") or f"Attack path {i}"
        risk = pd.get("risk_score", pd.get("score", "unknown"))
        scenarios.append({
            "title": str(title),
            "what_could_happen": _impact_narrative(top_findings[0] if top_findings else {"severity": "HIGH"}, playbook),
            "risk_score": risk,
        })

    return {
        "report_type": "executive_assurance",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "scan_id": scan_data.get("scan_id", "unknown"),
        "target": scan_data.get("target", "unknown"),
        "sector": playbook.get("sector"),
        "system_type": playbook.get("system_type"),
        "playbook": {
            "name": playbook.get("name"),
            "version": playbook.get("playbook_version"),
            "path": playbook.get("_path"),
        },
        "summary": summary,
        "top_risks": top_risks,
        "impact_scenarios": scenarios,
        "go_no_go": {
            "decision": decision,
            "reasons": failure_reasons or ["Within configured assurance thresholds."],
        },
        "technical_reference": {
            "findings_count": len(findings),
            "attack_paths_count": len(attack_paths),
        },
        "audit_reference": audit_ref or {},
    }


def _render_executive_html(report: Dict[str, Any]) -> str:
    decision = report.get("go_no_go", {}).get("decision", "GO")
    decision_color = "#c62828" if decision == "NO-GO" else "#2e7d32"
    risks = report.get("top_risks", [])
    scenarios = report.get("impact_scenarios", [])
    audit_ref = report.get("audit_reference", {}) or {}

    risk_rows = "".join(
        f"<tr><td>{html.escape(str(r.get('severity','')))}</td><td>{html.escape(str(r.get('issue','')))}</td><td>{html.escape(str(r.get('impact','')))}</td><td>{html.escape(str(r.get('effort_estimate',''))).upper()}</td></tr>"
        for r in risks
    ) or "<tr><td colspan='4'>No notable risk findings in this scan.</td></tr>"

    scenario_rows = "".join(
        f"<li><b>{html.escape(str(s.get('title','Scenario')))}</b>: {html.escape(str(s.get('what_could_happen','')))} (risk={html.escape(str(s.get('risk_score','n/a')))}).</li>"
        for s in scenarios
    ) or "<li>No attack-chain scenarios were detected.</li>"

    reasons = "".join(f"<li>{html.escape(str(r))}</li>" for r in report.get("go_no_go", {}).get("reasons", []))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>MISTCODER Executive Assurance Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #1e1e1e; }}
    h1, h2 {{ margin-bottom: 8px; }}
    .meta {{ color: #444; margin-bottom: 18px; }}
    .decision {{ font-size: 22px; font-weight: bold; color: {decision_color}; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 8px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
    th {{ background: #f7f7f7; text-align: left; }}
    .card {{ border: 1px solid #ddd; padding: 12px; margin: 14px 0; border-radius: 8px; }}
  </style>
</head>
<body>
  <h1>MISTCODER Executive Assurance Report</h1>
  <div class="meta">
    Sector: <b>{html.escape(str(report.get("sector","")))}</b> |
    System: <b>{html.escape(str(report.get("system_type","")))}</b> |
    Scan: <b>{html.escape(str(report.get("scan_id","")))}</b>
  </div>
  <div class="card">
    <div class="decision">Go/No-Go: {html.escape(str(decision))}</div>
    <ul>{reasons}</ul>
  </div>
  <h2>Top Risks (Plain Language)</h2>
  <table>
    <tr><th>Severity</th><th>Risk</th><th>What could happen</th><th>Effort</th></tr>
    {risk_rows}
  </table>
  <h2>Impact Scenarios</h2>
  <ul>{scenario_rows}</ul>
  <h2>Audit-Proof Reference (COVENANT)</h2>
  <div class="card">
    Ledger Hash: <code>{html.escape(str(audit_ref.get("ledger_hash", "n/a")))}</code><br/>
    Ledger Timestamp: <b>{html.escape(str(audit_ref.get("timestamp", "n/a")))}</b><br/>
    Chain Verified: <b>{html.escape(str(audit_ref.get("chain_verified", "n/a")))}</b>
  </div>
</body>
</html>"""


def _certify_scan_data(scan_data: Dict[str, Any], playbook: Dict[str, Any]) -> Dict[str, Any]:
    if _COVENANT is None:
        return {}
    summary = _findings_summary(scan_data.get("findings", []) or [])
    decision, _ = _decision_from_playbook(summary, playbook)
    target = str(scan_data.get("target", "") or "")
    target_hash = scan_data.get("target_hash") or _compute_target_hash(target)
    return _COVENANT.certify_scan(
        scan_data=scan_data,
        playbook=playbook,
        decision=decision,
        tool_version=MISTCODER_VERSION,
        target_hash=target_hash,
    )


def generate_executive_report(input_path: str, playbook_name: Optional[str] = None,
                              output_base: Optional[str] = None, auto_certify: bool = True):
    with open(input_path, "r", encoding="utf-8") as fh:
        scan_data = json.load(fh)
    playbook = _load_playbook(playbook_name)
    audit_ref = _certify_scan_data(scan_data, playbook) if auto_certify else {}
    report = _build_executive_report(scan_data, playbook, audit_ref=audit_ref)

    base = output_base or (input_path.rsplit(".", 1)[0] + "_executive")
    os.makedirs(os.path.dirname(base) or ".", exist_ok=True)
    json_path = base + ".json"
    html_path = base + ".html"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(_render_executive_html(report))
    return json_path, html_path, report


def certify_scan_file(input_path: str, playbook_name: Optional[str] = None):
    if _COVENANT is None:
        raise RuntimeError("COVENANT not available")
    with open(input_path, "r", encoding="utf-8") as fh:
        scan_data = json.load(fh)
    playbook = _load_playbook(playbook_name)
    certificate = _certify_scan_data(scan_data, playbook)
    return certificate, playbook


# ── Scan engine ───────────────────────────────────────────────────────────────
def run_scan(target: str, json_out: str = None, phantom: bool = False):
    print(BANNER)
    print(SEP)
    print("  SCANNING")
    print(SEP)

    scan_id = f"MSTC-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}-{hashlib.md5(target.encode()).hexdigest()[:6].upper()}"
    print(f"  Target  : {target}")
    print(f"  Scan ID : {scan_id}")
    print()

    # Kill-switch check
    if _COVENANT and not _COVENANT.is_clear():
        print("  🔴 COVENANT kill switch active — scanning blocked.")
        print("     Run: python mistcoder.py covenant status")
        return
    # Record scan start
    if _COVENANT:
        _COVENANT.record_scan_start(scan_id, target)

    files = collect_files(target)
    py_files  = files["py"]
    js_files  = files["js"] + files["ts"]
    bin_files = files["binary"]
    urls      = files["url"]

    total_files = sum(len(v) for v in files.values())
    if total_files == 0:
        print("  ✗ No scannable files found at target.")
        print("  Tip: Make sure the path exists and contains .py / .js / .ts files")
        return

    print(f"  Files   : {len(py_files)} Python | {len(js_files)} JS/TS | {len(bin_files)} Binary | {len(urls)} URLs")
    print()

    all_findings = []
    engines_ran  = 0

    # ── ORACLE — Python taint analysis ───────────────────────────────────────
    if py_files:
        ok, OracleWalker = _probe("ORACLE")
        if ok and OracleWalker:
            print(f"  Running ORACLE on {len(py_files)} Python file(s)...")
            try:
                walker = OracleWalker()
                for fpath in py_files:
                    findings = walker.scan_file(fpath)
                    all_findings.extend(findings)
                crit = sum(1 for f in all_findings if getattr(f, "severity", "") == "CRITICAL")
                high = sum(1 for f in all_findings if getattr(f, "severity", "") == "HIGH")
                print(f"  ✓ ORACLE: {len(all_findings)} findings ({crit} CRITICAL, {high} HIGH)")
                engines_ran += 1
            except Exception as e:
                print(f"  ✗ ORACLE error: {e}")
        else:
            print("  ○ ORACLE not available")

    # ── PARSER — Multi-language AST ──────────────────────────────────────────
    if py_files or js_files:
        ok, ParserCls = _probe("PARSER")
        if ok and ParserCls:
            print(f"  Running PARSER on {len(py_files)+len(js_files)} source file(s)...")
            try:
                parser   = ParserCls()
                ir_nodes = []
                for fpath in py_files + js_files:
                    nodes = parser.parse_file(fpath) if hasattr(parser, "parse_file") else \
                            parser.parse(open(fpath).read(), "python" if fpath.endswith(".py") else "javascript")
                    if nodes:
                        ir_nodes.extend(nodes if isinstance(nodes, list) else [nodes])
                print(f"  ✓ PARSER: {len(ir_nodes)} IR nodes extracted")
                engines_ran += 1
            except Exception as e:
                print(f"  ✗ PARSER error: {e}")

    # ── BINARY_LIFT ──────────────────────────────────────────────────────────
    if bin_files:
        ok, BinaryParser = _probe("BINARY_LIFT")
        if ok and BinaryParser:
            print(f"  Running BINARY_LIFT on {len(bin_files)} binary file(s)...")
            try:
                bp = BinaryParser()
                for fpath in bin_files:
                    bp.parse(fpath)
                print(f"  ✓ BINARY_LIFT: {len(bin_files)} binaries lifted")
                engines_ran += 1
            except Exception as e:
                print(f"  ✗ BINARY_LIFT error: {e}")

    # ── URL_SCANNER ──────────────────────────────────────────────────────────
    if urls:
        ok, URLScanner = _probe("URL_SCANNER")
        if ok and URLScanner:
            print(f"  Running URL_SCANNER on {len(urls)} URL(s)...")
            try:
                scanner    = URLScanner()
                url_result = scanner.scan(urls[0]) if hasattr(scanner, "scan") else {}
                print(f"  ✓ URL_SCANNER: complete")
                engines_ran += 1
            except Exception as e:
                print(f"  ✗ URL_SCANNER error: {e}")

    print()
    if engines_ran == 0:
        print("  No engines ran — check your target and available modules")
        return

    # ── IR_BRIDGE — merge all findings ───────────────────────────────────────
    unified_ir = None
    ok, IRBridge = _probe("IR_BRIDGE")
    if ok and IRBridge:
        try:
            bridge     = IRBridge()
            unified_ir = bridge.merge(all_findings)
        except Exception as e:
            print(f"  ⚠  IR_BRIDGE merge failed: {e}")

    # ── PHANTOM — TKG + attack path reasoning ────────────────────────────────
    attack_paths = []
    if phantom and unified_ir:
        print(SEP)
        print("  PHANTOM — Knowledge Graph + Attack Path Analysis")
        print(SEP)
        try:
            from modules.knowledge_graph.src.phantom import PhantomEngine
            ph = PhantomEngine()
            attack_paths = ph.run(unified_ir)
            print(f"  ✓ PHANTOM: {len(attack_paths)} ranked attack path(s) found")
        except Exception as e:
            print(f"  ✗ PHANTOM error: {e}")

    # ── COVENANT — record complete + compliance export ──────────────────────
    if _COVENANT and engines_ran > 0:
        cov_report = _COVENANT.record_scan_complete(scan_id, target, all_findings, attack_paths)
        base_path  = (json_out.rsplit(".", 1)[0] + "_compliance") if json_out else f"sandbox/{scan_id}_compliance"
        import os as _os; _os.makedirs("sandbox", exist_ok=True)
        written    = _COVENANT.export(cov_report, base_path, formats=["json", "md"])
        for w in written:
            print(f"  Compliance → {w}")

    # ── Print report ─────────────────────────────────────────────────────────
    _print_report(all_findings, attack_paths, scan_id)

    # ── JSON export ──────────────────────────────────────────────────────────
    if json_out:
        _export_json(all_findings, attack_paths, scan_id, json_out, unified_ir, target)
        print(f"\n  JSON saved → {json_out}")


def _print_report(findings, attack_paths, scan_id):
    if not findings and not attack_paths:
        return
    print(SEP)
    print("  FINDINGS")
    print(SEP)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_f  = sorted(findings, key=lambda f: sev_order.get(getattr(f, "severity", "INFO"), 4))

    for i, f in enumerate(sorted_f, 1):
        sev  = getattr(f, "severity",    "?")
        cwe  = getattr(f, "cwe",         "")
        file = getattr(f, "file_path",   getattr(f, "filename", ""))
        line = getattr(f, "line",        getattr(f, "line_number", ""))
        msg  = getattr(f, "description", getattr(f, "message", str(f)))
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(sev, "•")
        loc = f"{os.path.basename(str(file))}:{line}" if file else ""
        print(f"  {sev_icon} [{i:02d}] {sev:<8}  {cwe:<10}  {loc}")
        print(f"         {msg[:80]}")
        print()

    if attack_paths:
        print(SEP)
        print("  RANKED ATTACK PATHS")
        print(SEP)
        for i, path in enumerate(attack_paths[:5], 1):
            score = getattr(path, "score", getattr(path, "risk_score", "?"))
            title = getattr(path, "title", getattr(path, "name", f"Path {i}"))
            steps = getattr(path, "steps", getattr(path, "nodes", []))
            print(f"  [{i}] Risk {score}  —  {title}")
            for s in steps[:4]:
                print(f"        → {s}")
            print()

    print(SEP)
    print(f"  Scan complete  │  ID: {scan_id}  │  {len(findings)} finding(s)")
    print(SEP)


def _export_json(findings, attack_paths, scan_id, path, unified_ir=None, target=None):
    def _serialise(f):
        if hasattr(f, "__dict__"):
            return {k: str(v) for k, v in f.__dict__.items()}
        return str(f)

    data = {
        "scan_id":      scan_id,
        "timestamp":    datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "target":       target,
        "target_hash":  _compute_target_hash(target) if target else None,
        "findings":     [_serialise(f) for f in findings],
        "attack_paths": [_serialise(p) for p in attack_paths],
        "unified_ir":   unified_ir if isinstance(unified_ir, dict) else {},
    }
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, default=str)


# ── Self-test ─────────────────────────────────────────────────────────────────
def run_selftest():
    print(BANNER)
    print(SEP)
    print("  SELF-TEST")
    print(SEP)
    print()

    ok_oracle, OracleWalker = _probe("ORACLE")
    if ok_oracle and OracleWalker:
        try:
            walker = OracleWalker()
            _VULN = """
import subprocess, hashlib, os
SECRET_KEY = "hardcoded_secret_abc123"
def login(user_input):
    query = "SELECT * FROM users WHERE name='" + user_input + "'"
    subprocess.call(user_input, shell=True)
    h = hashlib.md5(b"password").hexdigest()
    return query
"""
            findings = walker.scan_code(_VULN, "<selftest>") if hasattr(walker, "scan_code") else \
                       walker.scan_source(_VULN, "<selftest>") if hasattr(walker, "scan_source") else []
            crit = sum(1 for f in findings if getattr(f, "severity", "") == "CRITICAL")
            high = sum(1 for f in findings if getattr(f, "severity", "") == "HIGH")
            print(f"  ✓ ORACLE: {len(findings)} findings ({crit} CRITICAL, {high} HIGH)")
        except Exception as e:
            print(f"  ✗ ORACLE: {e}")
    else:
        print("  ○ ORACLE: not available")

    ok_parser, ParserCls = _probe("PARSER")
    if ok_parser and ParserCls:
        try:
            parser = ParserCls()
            snippet = "def greet(name):\n    print(f'hello {name}')\n"
            nodes = parser.parse(snippet, "python") if hasattr(parser, "parse") else []
            print(f"  ✓ PARSER: {len(nodes) if isinstance(nodes, list) else 1} node(s) from test snippet")
        except Exception as e:
            print(f"  ✗ PARSER: {e}")
    else:
        print("  ○ PARSER: not available")

    ok_bridge, IRBridge = _probe("IR_BRIDGE")
    if ok_bridge and IRBridge:
        try:
            bridge  = IRBridge()
            result  = bridge.merge([])
            print(f"  ✓ IR_BRIDGE: merge() works correctly")
        except Exception as e:
            print(f"  ✗ IR_BRIDGE: {e}")
    else:
        print("  ○ IR_BRIDGE: not found (checked 3 locations)")

    try:
        from modules.knowledge_graph.src.phantom import PhantomEngine
        ph = PhantomEngine()
        print(f"  ✓ PHANTOM: engine loaded")
    except Exception as e:
        print(f"  ○ PHANTOM: {e}")

    print()
    run_status()


# ── Status display ────────────────────────────────────────────────────────────
def run_status():
    layers, status = get_module_status()
    print(BANNER)
    print(SEP)
    print("  MODULE STATUS")
    print(SEP)
    print()
    ready = 0
    total = 0
    for layer, mods in layers.items():
        print(f"  {layer}")
        for m in mods:
            ok = status[m]
            dot = "●" if ok else "○"
            label = "ready" if ok else "missing"
            print(f"    {dot}  {m:<22}  {label}")
            total += 1
            if ok: ready += 1
        print()
    print(f"  Engines ready: {ready}/{total}")
    print()


# ── CLI entry ─────────────────────────────────────────────────────────────────
def main():
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help", "help"):
        print(BANNER)
        print("  Usage:")
        print("    python mistcoder.py status")
        print("    python mistcoder.py selftest")
        print("    python mistcoder.py scan <target> [--json <out.json>] [--phantom]")
        print("    python mistcoder.py certify <scan_report.json> [--playbook <name_or_path>]")
        print("    python mistcoder.py report executive --input <scan_report.json> [--playbook <name_or_path>] [--output <base>]")
        print()
        print("  Examples:")
        print("    python mistcoder.py scan src/")
        print("    python mistcoder.py scan src/ --phantom")
        print("    python mistcoder.py scan src/ --json sandbox/report.json --phantom")
        print("    python mistcoder.py certify sandbox/report.json --playbook finance")
        print("    python mistcoder.py report executive --input sandbox/report.json --playbook government --output sandbox/gov_assurance")
        return

    cmd = args[0]

    if cmd == "status":
        run_status()

    elif cmd == "selftest":
        run_selftest()

    elif cmd == "scan":
        if len(args) < 2:
            print("  Error: provide a target path or URL")
            sys.exit(1)
        target   = args[1]
        json_out = None
        phantom  = "--phantom" in args
        if "--json" in args:
            idx      = args.index("--json")
            json_out = args[idx + 1] if idx + 1 < len(args) else "sandbox/report.json"
        run_scan(target, json_out=json_out, phantom=phantom)

    elif cmd == "certify":
        if len(args) < 2:
            print("  Error: provide a scan report JSON file")
            sys.exit(1)
        try:
            playbook_name = _arg_value(args, "--playbook", "finance")
            cert, playbook = certify_scan_file(args[1], playbook_name=playbook_name)
            print(SEP)
            print("  SCAN CERTIFIED")
            print(SEP)
            print(f"  Scan ID:        {cert.get('scan_id')}")
            print(f"  Playbook:       {playbook.get('name')} v{playbook.get('playbook_version')}")
            print(f"  Ledger hash:    {cert.get('ledger_hash')}")
            print(f"  Timestamp:      {cert.get('timestamp')}")
            print(f"  Chain verified: {cert.get('chain_verified')}")
            print(SEP)
        except Exception as e:
            print(f"  Error: {e}")
            sys.exit(1)

    elif cmd == "report":
        sub = args[1] if len(args) > 1 else ""
        if sub != "executive":
            print("  Error: supported report mode is: executive")
            sys.exit(1)
        input_path = _arg_value(args, "--input")
        if not input_path:
            print("  Error: provide --input <scan_report.json>")
            sys.exit(1)
        playbook_name = _arg_value(args, "--playbook", "finance")
        output_base = _arg_value(args, "--output", None)
        try:
            out_json, out_html, report = generate_executive_report(
                input_path=input_path,
                playbook_name=playbook_name,
                output_base=output_base,
                auto_certify=True,
            )
            print(SEP)
            print("  EXECUTIVE ASSURANCE REPORT")
            print(SEP)
            print(f"  Decision:   {report.get('go_no_go', {}).get('decision')}")
            print(f"  JSON:       {out_json}")
            print(f"  HTML:       {out_html}")
            if report.get("audit_reference"):
                print(f"  Ledger ref: {report['audit_reference'].get('ledger_hash')}")
            print(SEP)
        except Exception as e:
            print(f"  Error: {e}")
            sys.exit(1)

    elif cmd == "covenant":
        sub = args[1] if len(args) > 1 else "status"
        if _COVENANT is None:
            print("  COVENANT not available — ensure modules/oversight/src/covenant.py exists")
            return
        if sub == "status":
            s  = _COVENANT.status()
            ok = s["chain_valid"]
            ks = s["kill_switch_active"]
            print(BANNER)
            print(SEP)
            print("  COVENANT AUDIT STATUS")
            print(SEP)
            print(f"  Chain:        {chr(10003) if ok else chr(10007)} {s['chain_message']}")
            print(f"  Records:      {s['total_records']}")
            print(f"  Scans logged: {s['total_scans']}")
            print(f"  Kill switch:  {'ACTIVE' if ks else 'clear'}")
            if s.get('last_scan'): print(f"  Last scan:    {s['last_scan']}")
            print()
        elif sub == "verify":
            ok, msg = _COVENANT.verify()
            print(f"\n  {chr(10003) if ok else chr(10007)} {msg}\n")
        elif sub == "clear":
            _COVENANT.disengage_kill_switch()
        elif sub == "export" and len(args) >= 3:
            with open(args[2]) as fh:
                data = json.load(fh)
            rep     = _COVENANT.reporter.build_report(
                data.get("scan_id","unknown"), data.get("target","unknown"),
                data.get("findings",[]), data.get("attack_paths",[]))
            base    = args[3] if len(args) >= 4 else "sandbox/compliance_export"
            written = _COVENANT.export(rep, base, formats=["json","csv","md"])
            for w in written: print(f"  Wrote: {w}")

    else:
        print(f"  Unknown command: {cmd}")
        print("  Run: python mistcoder.py --help")


if __name__ == "__main__":
    main()
