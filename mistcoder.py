#!/usr/bin/env python3
"""
MISTCODER — NEXUS Unified Intelligence CLI  v0.3.0
Fixes: IR_BRIDGE path detection + directory scan routing + PHANTOM integration
"""
import sys, os, json, time, hashlib, datetime, pathlib

ROOT = pathlib.Path(__file__).parent
sys.path.insert(0, str(ROOT))

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

    # ── Print report ─────────────────────────────────────────────────────────
    _print_report(all_findings, attack_paths, scan_id)

    # ── JSON export ──────────────────────────────────────────────────────────
    if json_out:
        _export_json(all_findings, attack_paths, scan_id, json_out, unified_ir)
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


def _export_json(findings, attack_paths, scan_id, path, unified_ir=None):
    def _serialise(f):
        if hasattr(f, "__dict__"):
            return {k: str(v) for k, v in f.__dict__.items()}
        return str(f)

    data = {
        "scan_id":      scan_id,
        "timestamp":    datetime.datetime.utcnow().isoformat(),
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
        print()
        print("  Examples:")
        print("    python mistcoder.py scan src/")
        print("    python mistcoder.py scan src/ --phantom")
        print("    python mistcoder.py scan src/ --json sandbox/report.json --phantom")
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

    else:
        print(f"  Unknown command: {cmd}")
        print("  Run: python mistcoder.py --help")


if __name__ == "__main__":
    main()
