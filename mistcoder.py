#!/usr/bin/env python3
"""
MISTCODER — NEXUS
mistcoder.py  —  The unified intelligence CLI.

Routes any target through the right engine(s), merges all findings
into one UnifiedIR, feeds it to the knowledge graph, and prints
a single authoritative intelligence report.

Supported targets:
    mistcoder scan <file.py>           Python file  → ORACLE
    mistcoder scan <file.js>           JS file      → PARSER
    mistcoder scan <directory/>        Directory    → ORACLE + PARSER
    mistcoder scan <https://url>       URL          → URL_SCANNER
    mistcoder scan <file.py> --url <u> Both         → ORACLE + URL_SCANNER (merged)

    mistcoder status                   Show what modules are available
    mistcoder selftest                 Full self-test of all engines

Zero external dependencies. Python 3.8+
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Path bootstrap ──────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent
_SRC  = _ROOT / "modules" / "ingestion" / "src"
sys.path.insert(0, str(_SRC))
sys.path.insert(0, str(_ROOT))


# ── Lazy engine imports (graceful if a module is missing) ───────────────────

def _try_import(module_name: str, symbol: str):
    try:
        import importlib
        mod = importlib.import_module(module_name)
        return getattr(mod, symbol, None)
    except ImportError:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Colours
# ─────────────────────────────────────────────────────────────────────────────

_NO_COLOR = os.environ.get("NO_COLOR") or not sys.stdout.isatty()

def _c(code, t): return t if _NO_COLOR else f"\033[{code}m{t}\033[0m"

RED     = lambda t: _c("91", t)
YELLOW  = lambda t: _c("93", t)
GREEN   = lambda t: _c("92", t)
CYAN    = lambda t: _c("96", t)
BLUE    = lambda t: _c("94", t)
MAGENTA = lambda t: _c("95", t)
BOLD    = lambda t: _c("1",  t)
DIM     = lambda t: _c("2",  t)
WHITE   = lambda t: _c("97", t)

SEV = {
    "CRITICAL": lambda t: RED(BOLD(t)),
    "HIGH":     lambda t: RED(t),
    "MEDIUM":   lambda t: YELLOW(t),
    "LOW":      lambda t: GREEN(t),
    "INFO":     lambda t: DIM(t),
}

def sev_badge(s: str) -> str:
    fn = SEV.get(s, DIM)
    return fn(f"[{s}]")

def _div(c="─", w=72): return DIM(c * w)
def _section(t): return f"\n{_div()}\n  {BOLD(CYAN(t))}\n{_div()}"
def _header(t):  return f"\n{_div('═')}\n  {BOLD(WHITE(t))}\n{_div('═')}"


# ─────────────────────────────────────────────────────────────────────────────
# NEXUS banner
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
███╗   ███╗██╗███████╗████████╗ ██████╗ ██████╗ ██████╗ ███████╗██████╗
████╗ ████║██║██╔════╝╚══██╔══╝██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗
██╔████╔██║██║███████╗   ██║   ██║     ██║   ██║██║  ██║█████╗  ██████╔╝
██║╚██╔╝██║██║╚════██║   ██║   ██║     ██║   ██║██║  ██║██╔══╝  ██╔══██╗
██║ ╚═╝ ██║██║███████║   ██║   ╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║
╚═╝     ╚═╝╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝"""


def _print_banner():
    print(CYAN(BOLD(BANNER)))
    print(DIM("  NEXUS — Unified Intelligence CLI  │  All engines, one report\n"))


# ─────────────────────────────────────────────────────────────────────────────
# Engine availability check
# ─────────────────────────────────────────────────────────────────────────────

def _check_engines() -> dict[str, bool]:
    available = {}
    available["ORACLE"]      = (_SRC / "python_ast_walker.py").exists()
    available["PARSER"]      = (_SRC / "parser.py").exists()
    available["URL_SCANNER"] = (_SRC / "url_scanner.py").exists()
    available["IR_BRIDGE"]   = (_SRC / "ir_bridge.py").exists()

    kg_src = _ROOT / "modules" / "knowledge_graph" / "src"
    available["TKG_BUILDER"]    = (kg_src / "threat_kg_builder.py").exists()
    available["ATTACK_FINDER"]  = (kg_src / "attack_path_finder.py").exists()

    rs_src = _ROOT / "modules" / "reasoning" / "src"
    available["REASONING"]   = (rs_src / "attack_path_reasoning.py").exists()
    available["EXPLAINABILITY"] = (rs_src / "explainability_chains.py").exists()

    bl_src = _ROOT / "modules" / "binary_lifting" / "src"
    available["BINARY_LIFT"] = (bl_src / "binary_lifting.py").exists()

    return available


def _print_status():
    _print_banner()
    engines = _check_engines()
    print(_section("MODULE STATUS"))
    print()

    groups = [
        ("Layer 1 — Ingestion",   ["ORACLE", "PARSER", "URL_SCANNER", "BINARY_LIFT"]),
        ("Layer 2 — Bridge",      ["IR_BRIDGE"]),
        ("Layer 3 — Knowledge",   ["TKG_BUILDER", "ATTACK_FINDER"]),
        ("Layer 4 — Reasoning",   ["REASONING", "EXPLAINABILITY"]),
    ]

    for group_name, keys in groups:
        print(f"  {BOLD(group_name)}")
        for k in keys:
            ok = engines.get(k, False)
            icon = GREEN("●") if ok else RED("○")
            state = GREEN("ready") if ok else DIM("missing")
            print(f"    {icon}  {k:<22} {state}")
        print()

    ready = sum(engines.values())
    total = len(engines)
    print(f"  {BOLD('Engines ready:')} {GREEN(str(ready))}/{total}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Scan orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def _generate_scan_id(target: str) -> str:
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    h    = hashlib.sha256(target.encode()).hexdigest()[:6].upper()
    return f"MSTC-{ts}-{h}"


def _run_oracle(target: str, scan_id: str):
    """Run ORACLE taint engine on file or directory."""
    from python_ast_walker import analyse_file, analyse_directory
    from ir_bridge import from_oracle

    print(f"  {CYAN('▶')} ORACLE — Python static analysis")
    t0 = time.perf_counter()
    path = Path(target)
    if path.is_file():
        results = [analyse_file(str(path))]
    else:
        results = analyse_directory(str(path))
    elapsed = int((time.perf_counter() - t0) * 1000)

    files_hit = sum(1 for r in results if r.finding_count > 0)
    print(f"    {DIM(f'{len(results)} files  |  {files_hit} with findings  |  {elapsed}ms')}")

    ir = from_oracle(results, scan_id, target)
    return ir, results


def _run_parser(target: str, scan_id: str):
    """Run multi-language parser on file or directory."""
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location("ingestion_parser", str(_SRC / "parser.py"))
    _mod  = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    IngestionEngine = _mod.IngestionEngine

    from ir_bridge import from_parser, merge, UnifiedIR

    print(f"  {CYAN('▶')} PARSER — Multi-language AST (py/js/ts)")
    t0 = time.perf_counter()

    engine = IngestionEngine()
    path   = Path(target)

    if path.is_file():
        ir_dicts = [engine.ingest_file(str(path))]
    else:
        ir_dicts = engine.ingest_directory(str(path))

    elapsed = int((time.perf_counter() - t0) * 1000)
    total_nodes = sum(d.get("metadata", {}).get("node_count", 0)
                      for d in ir_dicts if isinstance(d, dict))
    print(f"    {DIM(f'{len(ir_dicts)} files  |  {total_nodes} nodes  |  {elapsed}ms')}")

    irs = [from_parser(d, scan_id) for d in ir_dicts if isinstance(d, dict)]
    if not irs:
        return None
    combined = irs[0]
    for other in irs[1:]:
        combined.findings.extend(other.findings)
    combined.metadata["parser_files"] = len(ir_dicts)
    return combined


def _run_url_scanner(url: str, scan_id: str, probe: bool = True):
    """Run URL scanner."""
    from url_scanner import URLScanner
    from ir_bridge import from_url_scanner

    print(f"  {CYAN('▶')} URL_SCANNER — Remote target analysis")
    t0 = time.perf_counter()

    scanner = URLScanner(probe_endpoints=probe, crawl_links=True, verbose=False)
    ir_dict = scanner.scan(url)
    elapsed = int((time.perf_counter() - t0) * 1000)

    meta = ir_dict.get("metadata", {})
    status    = meta.get("status_code", "?")
    dangerous = meta.get("dangerous_calls", 0)
    secrets   = meta.get("secret_flags", 0)
    print(f"    {DIM(f'Status {status}  |  {dangerous} dangerous  |  {secrets} secrets  |  {elapsed}ms')}")

    return from_url_scanner(ir_dict, scan_id)


def _try_feed_tkg(unified_ir, scan_id: str, output_dir: str) -> str | None:
    """
    Try to feed UnifiedIR into modules/knowledge_graph/threat_kg_builder.py.
    Returns path to output file, or None if TKG module not available.
    """
    tkg_path = _ROOT / "modules" / "knowledge_graph" / "src" / "threat_kg_builder.py"
    if not tkg_path.exists():
        return None

    # Write the unified IR to sandbox/ for the TKG builder to pick up
    os.makedirs(output_dir, exist_ok=True)
    ir_file = os.path.join(output_dir, f"{scan_id}_unified_ir.json")
    unified_ir.export(ir_file)
    return ir_file


# ─────────────────────────────────────────────────────────────────────────────
# Report renderer
# ─────────────────────────────────────────────────────────────────────────────

def _render_report(unified_ir, elapsed_total_ms: int, ir_file: str | None,
                   engines_used: list[str]):
    from ir_bridge import UnifiedIR

    ir  = unified_ir
    ts  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    print(_header("NEXUS INTELLIGENCE REPORT"))
    print(f"  {DIM('Scan ID  :')} {CYAN(ir.scan_id)}")
    print(f"  {DIM('Target   :')} {CYAN(ir.target)}")
    print(f"  {DIM('Timestamp:')} {ts}")
    print(f"  {DIM('Engines  :')} {', '.join(engines_used)}")
    print(f"  {DIM('Duration :')} {elapsed_total_ms}ms")

    print(_section("FINDINGS SUMMARY"))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in ir.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"  {DIM('Total findings:')} {BOLD(str(ir.total))}\n")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        c = counts.get(sev, 0)
        if c == 0:
            continue
        bar = "█" * min(c, 50)
        fn  = SEV.get(sev, DIM)
        print(f"  {fn(f'● {sev:<10}')} {str(c):<4}  {DIM(bar)}")

    # ── Top findings ──────────────────────────────────────────────────
    top = [f for f in ir.findings if f.severity in ("CRITICAL", "HIGH")]
    top.sort(key=lambda f: ["CRITICAL", "HIGH"].index(f.severity))

    if top:
        print(_section(f"CRITICAL & HIGH FINDINGS  ({len(top)} total)"))
        shown_locs: set[tuple[str, str]] = set()
        for f in top:
            key = (f.title, f.location)
            if key in shown_locs:
                continue
            shown_locs.add(key)
            engine_tag = DIM(f"[{f.source_engine}]")
            cwe        = DIM(f.cwe_ids[0]) if f.cwe_ids else ""
            loc        = DIM(os.path.basename(f.location) if "/" in f.location
                             or "\\" in f.location else f.location)
            print(f"\n  {sev_badge(f.severity)}  {BOLD(f.title)}")
            print(f"    {DIM('Location:')} {loc}  {engine_tag}  {cwe}")
            print(f"    {DIM('Detail  :')} {f.detail[:90]}")
            if f.remediation:
                print(f"    {DIM('Fix     :')} {GREEN(f.remediation)}")

    # ── By engine breakdown ───────────────────────────────────────────
    if len(engines_used) > 1:
        print(_section("FINDINGS BY ENGINE"))
        from collections import Counter
        by_engine = Counter(f.source_engine for f in ir.findings)
        for eng, count in sorted(by_engine.items(), key=lambda x: -x[1]):
            print(f"  {CYAN(f'{eng:<20}')} {count} findings")

    # ── Knowledge graph export ────────────────────────────────────────
    if ir_file:
        print(_section("KNOWLEDGE GRAPH"))
        print(f"  {GREEN('✓')} UnifiedIR exported → {CYAN(ir_file)}")
        print(f"  {DIM('Feed to:')} modules/knowledge_graph/src/threat_kg_builder.py")
        print(f"  {DIM('Then   :')} modules/reasoning/src/attack_path_reasoning.py")

    # ── Risk verdict ──────────────────────────────────────────────────
    print(_section("RISK VERDICT"))
    c, h = counts.get("CRITICAL", 0), counts.get("HIGH", 0)

    if c >= 3:
        print(f"\n  {RED(BOLD('CRITICAL RISK — Immediate action required'))}")
        print(f"  {RED('Stop all deployment. Remediate CRITICAL findings now.')}")
    elif c >= 1:
        print(f"\n  {RED(BOLD('HIGH RISK — Critical vulnerabilities present'))}")
        print(f"  {YELLOW('Address all CRITICAL findings before production deployment.')}")
    elif h >= 3:
        print(f"\n  {YELLOW(BOLD('ELEVATED RISK — Multiple high-severity findings'))}")
        print(f"  {YELLOW('Schedule remediation sprint before next release.')}")
    elif h >= 1:
        print(f"\n  {YELLOW(BOLD('MODERATE RISK — High-severity findings present'))}")
        print(f"  {GREEN('Prioritize HIGH findings in next sprint.')}")
    else:
        print(f"\n  {GREEN(BOLD('LOW RISK — No critical or high-severity findings'))}")
        print(f"  {GREEN('Continue standard security review cadence.')}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

def _selftest():
    """Run ORACLE self-test then show full status."""
    _print_banner()
    print(_section("SELF-TEST"))

    # ORACLE self-test
    print(f"\n  {BOLD('Testing ORACLE...')}")
    try:
        from python_ast_walker import analyse_file
        from ir_bridge import from_oracle
        import tempfile, os

        _VULN = '''
from flask import request
import os, hashlib, pickle
SECRET_KEY = "sk_live_TEST_abc123XYZ_sentinel_key_42"
def f():
    q = request.args.get("q")
    os.system(q)
    hashlib.md5(b"x")
    pickle.loads(request.data)
'''
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(_VULN)
            tmp = f.name
        try:
            result  = analyse_file(tmp)
            unified = from_oracle([result], "SELFTEST-001", tmp)
            crits   = sum(1 for f in unified.findings if f.severity == "CRITICAL")
            highs   = sum(1 for f in unified.findings if f.severity == "HIGH")
            total   = len(unified.findings)
            if total >= 3:
                print(f"  {GREEN('✓')} ORACLE: {total} findings ({crits} CRITICAL, {highs} HIGH)")
            else:
                print(f"  {YELLOW('⚠')} ORACLE: only {total} findings — check engine")
        finally:
            os.unlink(tmp)
    except Exception as e:
        print(f"  {RED('✗')} ORACLE: {e}")

    # PARSER test
    print(f"\n  {BOLD('Testing PARSER...')}")
    try:
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location(
            "ingestion_parser", str(_SRC / "parser.py"))
        _mod  = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        _code = 'import os\ndef run(cmd):\n    os.system(cmd)\npassword = "hardcoded123"\n'
        p  = _mod.PythonParser(_code, "test.py")
        ir = p.parse()
        n  = ir["metadata"]["node_count"]
        print(f"  {GREEN('✓')} PARSER: {n} nodes extracted from test snippet")
    except Exception as e:
        print(f"  {RED('✗')} PARSER: {e}")

    # IR_BRIDGE test
    print(f"\n  {BOLD('Testing IR_BRIDGE...')}")
    try:
        from ir_bridge import merge, UnifiedIR
        u1 = UnifiedIR("test", "T1", "2025", ["ORACLE"], [])
        u2 = UnifiedIR("test", "T1", "2025", ["PARSER"], [])
        m  = merge(u1, u2)
        assert "ORACLE" in m.engines_used and "PARSER" in m.engines_used
        print(f"  {GREEN('✓')} IR_BRIDGE: merge() works correctly")
    except Exception as e:
        print(f"  {RED('✗')} IR_BRIDGE: {e}")

    print()
    _print_status()


# ─────────────────────────────────────────────────────────────────────────────
# Main scan command
# ─────────────────────────────────────────────────────────────────────────────

def _cmd_scan(args):
    _print_banner()

    target      = args.target
    is_url      = target.startswith(("http://", "https://")) or args.url
    scan_id     = _generate_scan_id(target)
    output_dir  = args.output or "sandbox"
    t0_total    = time.perf_counter()
    engines_run: list[str] = []

    print(_section("SCANNING"))
    print(f"  {DIM('Target  :')} {CYAN(target)}")
    print(f"  {DIM('Scan ID :')} {scan_id}")
    print()

    all_irs = []

    # ── File / directory targets ──────────────────────────────────────
    if not is_url or args.url:
        path = Path(target if not args.url else args.url)

        # ORACLE — Python taint analysis
        if _check_engines().get("ORACLE") and not args.no_oracle:
            py_files = (list(path.rglob("*.py")) if path.is_dir()
                        else [path] if path.suffix == ".py" else [])
            if py_files:
                oracle_ir, _ = _run_oracle(str(path), scan_id)
                all_irs.append(oracle_ir)
                engines_run.append("ORACLE")

        # PARSER — multi-language
        if _check_engines().get("PARSER") and not args.no_parser:
            ext = path.suffix.lower() if path.is_file() else ""
            if path.is_dir() or ext in (".py", ".js", ".ts", ".jsx", ".tsx"):
                parser_ir = _run_parser(str(path), scan_id)
                if parser_ir and parser_ir.total > 0:
                    all_irs.append(parser_ir)
                    if "PARSER" not in engines_run:
                        engines_run.append("PARSER")

    # ── URL target ───────────────────────────────────────────────────
    if is_url:
        url = args.url or target
        if _check_engines().get("URL_SCANNER") and not args.no_url:
            url_ir = _run_url_scanner(url, scan_id, probe=not args.no_probe)
            all_irs.append(url_ir)
            engines_run.append("URL_SCANNER")

    if not all_irs:
        print(RED("\n  No engines ran — check your target and available modules\n"))
        return 2

    # ── Merge all engine outputs ──────────────────────────────────────
    from ir_bridge import merge
    print(f"\n  {CYAN('▶')} Merging {len(all_irs)} engine output(s)...")
    unified = all_irs[0] if len(all_irs) == 1 else merge(*all_irs)
    unified.scan_id = scan_id

    # ── Feed to knowledge graph ───────────────────────────────────────
    ir_file = None
    if not args.no_tkg:
        ir_file = _try_feed_tkg(unified, scan_id, output_dir)
        if ir_file:
            print(f"  {GREEN('✓')} UnifiedIR → {ir_file}")

    # ── JSON export ───────────────────────────────────────────────────
    if args.json:
        unified.export(args.json)
        print(f"  {GREEN('✓')} JSON export → {args.json}")

    elapsed = int((time.perf_counter() - t0_total) * 1000)

    # ── Render report ─────────────────────────────────────────────────
    _render_report(unified, elapsed, ir_file, engines_run)

    return 1 if unified.critical > 0 else 0


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="mistcoder",
        description="MISTCODER NEXUS — Unified Intelligence CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  mistcoder scan <target>       Scan a file, directory, or URL
  mistcoder status              Show module availability
  mistcoder selftest            Run full engine self-test

Scan examples:
  python mistcoder.py scan src/
  python mistcoder.py scan app.py
  python mistcoder.py scan https://target.com
  python mistcoder.py scan src/ --url https://target.com
  python mistcoder.py scan src/ --json report.json
        """,
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    sp = sub.add_parser("scan", help="Scan a target")
    sp.add_argument("target",        help="File, directory, or URL")
    sp.add_argument("--url",         help="Also scan this URL alongside the file target")
    sp.add_argument("--json",        metavar="FILE", help="Export unified JSON")
    sp.add_argument("--output",      metavar="DIR",  default="sandbox",
                                     help="Output directory (default: sandbox/)")
    sp.add_argument("--no-oracle",   action="store_true", help="Skip ORACLE engine")
    sp.add_argument("--no-parser",   action="store_true", help="Skip PARSER engine")
    sp.add_argument("--no-url",      action="store_true", help="Skip URL_SCANNER")
    sp.add_argument("--no-probe",    action="store_true", help="Skip endpoint probing")
    sp.add_argument("--no-tkg",      action="store_true", help="Skip TKG export")

    # status
    sub.add_parser("status", help="Show module availability")

    # selftest
    sub.add_parser("selftest", help="Run engine self-tests")

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(_cmd_scan(args))
    elif args.command == "status":
        _print_status()
    elif args.command == "selftest":
        _selftest()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
