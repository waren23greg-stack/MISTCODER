# blockchain/mistcoder_cli.py
# MISTCODER Unified CLI — Layer 10 (Enhanced)
#
# Paste this entire file over your existing blockchain/mistcoder_cli.py

from __future__ import annotations

import sys
import json
import time
import logging
import argparse
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    filename="mistcoder.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("mistcoder")

# ── ANSI colours ──────────────────────────────────────────────────────────────
try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
    C = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH"    : Fore.YELLOW + Style.BRIGHT,
        "MEDIUM"  : Fore.CYAN,
        "LOW"     : Fore.GREEN,
        "RESET"   : Style.RESET_ALL,
        "BOLD"    : Style.BRIGHT,
    }
except Exception:
    C = {k: "" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "RESET", "BOLD")}

BANNER = r"""
  ███╗   ███╗██╗███████╗████████╗ ██████╗ ██████╗ ██████╗ ███████╗██████╗
  ████╗ ████║██║██╔════╝╚══██╔══╝██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗
  ██╔████╔██║██║███████╗   ██║   ██║     ██║   ██║██║  ██║█████╗  ██████╔╝
  ██║╚██╔╝██║██║╚════██║   ██║   ██║     ██║   ██║██║  ██║██╔══╝  ██╔══██╗
  ██║ ╚═╝ ██║██║███████║   ██║   ╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║
  ╚═╝     ╚═╝╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
  Threat-Native Blockchain  ·  Neural Oracle  ·  Trinity Consensus
"""

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
LANG_LABELS = {
    "python": "Python",
    "javascript": "JavaScript",
    "go": "Go",
    "py": "Python",
    "js": "JavaScript",
}
LANG_KEY_MAP = {"py": "py", "js": "js", "go": "go", "python": "py", "javascript": "js"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _ts_from_float(raw) -> str:
    try:
        return datetime.utcfromtimestamp(float(raw)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(raw)[:19]


def _pad(value, width: int) -> str:
    return str(value).ljust(width)


def _colour(sev: str, text: str) -> str:
    return C.get(sev.upper(), "") + text + C["RESET"]


# ══════════════════════════════════════════════════════════════════════════════
# SCANNERS
# ══════════════════════════════════════════════════════════════════════════════

def _empty_result(language: str, target: Path) -> dict:
    return {
        "language": language,
        "scanner": f"MISTCODER {language.title()} Scanner",
        "target": str(target),
        "files": 0,
        "findings": [],
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
    }


def run_python_scan(target: Path) -> dict:
    try:
        from blockchain.phantom_scanner import PhantomScanner
        scanner = PhantomScanner()
        findings = scanner.scan_directory(str(target))
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        for f in findings:
            sev = f.get("severity", "LOW").lower()
            summary[sev] = summary.get(sev, 0) + 1
            summary["total"] += 1
        log.info(f"PY SCANNER: {len(findings)} findings")
        return {
            "language": "python",
            "scanner": "MISTCODER Python Scanner",
            "target": str(target),
            "files": 0,
            "findings": findings,
            "summary": summary,
        }
    except Exception as e:
        log.error("Python scanner error", exc_info=True)
        print(f"[CLI] Python scanner error: {e}")
        return _empty_result("python", target)


def run_js_scan(target: Path) -> dict:
    try:
        from blockchain.lang.js_scanner import JSScanner
        result = JSScanner().scan_directory(target)
        log.info(f"JS SCANNER: {result.get('files',0)} files, {len(result.get('findings',[]))} findings")
        return result
    except Exception as e:
        log.error("JS scanner error", exc_info=True)
        print(f"[CLI] JS scanner error: {e}")
        return _empty_result("javascript", target)


def run_go_scan(target: Path) -> dict:
    try:
        from blockchain.lang.go_scanner import GoScanner
        result = GoScanner().scan_directory(target)
        log.info(f"GO SCANNER: {result.get('files',0)} files, {len(result.get('findings',[]))} findings")
        return result
    except Exception as e:
        log.error("Go scanner error", exc_info=True)
        print(f"[CLI] Go scanner error: {e}")
        return _empty_result("go", target)


LANG_RUNNERS = {"py": run_python_scan, "js": run_js_scan, "go": run_go_scan}


# ══════════════════════════════════════════════════════════════════════════════
# TRINITY PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def certify_findings(all_scan_results: list) -> dict:
    from blockchain.lang.lang_bridge import findings_to_kill_chains
    from blockchain.phantom_chain_bridge import PhantomChainBridge
    from blockchain.chain_persistence import MistChainPersistence

    print()
    print("  ┌─ TRINITY PIPELINE ──────────────────────────────────")
    print("  │  Loading chain from disk...")

    loaded_chain = MistChainPersistence.load()
    bridge = PhantomChainBridge(node_id="NODE-UNIFIED")
    bridge.chain = loaded_chain

    certified, blocked, deduped = [], [], []
    prefix_map = {"python": "PY", "javascript": "JA", "go": "GO"}

    for scan in all_scan_results:
        lang = scan.get("language", "unknown")
        findings = scan.get("findings", [])
        if not findings:
            continue

        prefix = prefix_map.get(lang, lang[:2].upper())
        chains = findings_to_kill_chains(findings, lang)

        for i, chain in enumerate(chains, 1):
            fid = f"UNIFIED-{prefix}-{i:04d}"
            existing = MistChainPersistence.lookup(fid)

            if existing:
                deduped.append(fid)
                print(f"  │  ⟳ {fid} already on chain (block {existing['block']})")
                continue

            steps = []
            seen = set()
            for node in chain["nodes"]:
                for key in ("call_name", "cwe_id"):
                    val = node.get(key, "")
                    if val and val not in seen:
                        steps.append(val)
                        seen.add(val)

            block = bridge.phantom_submit(
                finding_id=fid,
                steps=steps,
                score=chain["score"],
                stealth=chain["stealth"],
                novelty=chain["novelty"],
            )

            if block:
                certified.append({
                    "finding_id": fid,
                    "language": lang,
                    "block": block.index,
                    "hash": block.hash[:20],
                    "score": chain["score"],
                    "file": chain["file"],
                    "steps": steps,
                })
                print(f"  │  ✓ Block {block.index} | {fid} | score={chain['score']}")
            else:
                blocked.append(fid)
                print(f"  │  ✗ {fid} blocked by COVENANT")

    if certified:
        MistChainPersistence.save(bridge.chain)

    print("  └─────────────────────────────────────────────────────")
    return {
        "certified": certified,
        "blocked": blocked,
        "deduplicated": deduped,
    }


# ══════════════════════════════════════════════════════════════════════════════
# REPORT BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def build_report(scan_results: list, trinity: dict, elapsed: float, top_n: int = 10) -> dict:
    total_findings = sum(len(s.get("findings", [])) for s in scan_results)
    total_files = sum(s.get("files", 0) for s in scan_results)

    agg = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for s in scan_results:
        for sev in agg:
            agg[sev] += s.get("summary", {}).get(sev, 0)

    # Flatten findings and tag with language
    all_findings = []
    for s in scan_results:
        lang = s.get("language", "unknown")
        for f in s.get("findings", []):
            tagged = dict(f)
            tagged["_lang"] = lang
            all_findings.append(tagged)

    top_findings = sorted(
        all_findings,
        key=lambda f: (
            -f.get("cvss_score", 0),
            SEVERITY_ORDER.get(f.get("severity", "LOW").upper(), 9)
        )
    )[:top_n]

    return {
        "report_version": "1.0",
        "scanner": "MISTCODER Unified CLI",
        "scanned_at": _utc_now(),
        "elapsed_s": round(elapsed, 2),
        "languages": [s.get("language") for s in scan_results],
        "totals": {
            "files": total_files,
            "findings": total_findings,
            **agg,
        },
        "per_language": [
            {
                "language": s.get("language"),
                "files": s.get("files", 0),
                "findings": len(s.get("findings", [])),
                "summary": s.get("summary", {}),
            }
            for s in scan_results
        ],
        "trinity": {
            "certified": len(trinity.get("certified", [])),
            "blocked": len(trinity.get("blocked", [])),
            "deduplicated": len(trinity.get("deduplicated", [])),
            "blocks": trinity.get("certified", []),
        },
        "top_findings": [
            {
                "file": f.get("file", ""),
                "line": f.get("line", 0),
                "language": f.get("_lang", ""),
                "call_name": f.get("call_name", ""),
                "cwe_id": f.get("cwe_id", ""),
                "severity": f.get("severity", ""),
                "cvss": f.get("cvss_score", 0),
                "title": f.get("title", ""),
            }
            for f in top_findings
        ],
        "all_findings": [
            {
                "file": f.get("file", ""),
                "line": f.get("line", 0),
                "language": f.get("_lang", ""),
                "call_name": f.get("call_name", ""),
                "cwe_id": f.get("cwe_id", ""),
                "severity": f.get("severity", ""),
                "cvss": f.get("cvss_score", 0),
                "title": f.get("title", ""),
            }
            for f in all_findings
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# CONSOLE PRINTER
# ══════════════════════════════════════════════════════════════════════════════

def print_report(report: dict, top_n: int = 10):
    t = report["totals"]
    tri = report["trinity"]
    W = 38

    print()
    print(C["BOLD"] + "  ╔══════════════════════════════════════════════════════╗" + C["RESET"])
    print(C["BOLD"] + "  ║           MISTCODER UNIFIED SCAN REPORT             ║" + C["RESET"])
    print("  ╠══════════════════════════════════════════════════════╣")
    print(f"  ║  Scanned at : {_pad(report['scanned_at'], W)}║")
    print(f"  ║  Languages  : {_pad(', '.join(report['languages']), W)}║")
    print(f"  ║  Files      : {_pad(t['files'], W)}║")
    print(f"  ║  Elapsed    : {_pad(str(report['elapsed_s']) + 's', W)}║")
    print("  ╠══════════════════════════════════════════════════════╣")
    print("  ║  FINDINGS                                            ║")
    print(f"  ║    Total    : {_pad(t['findings'], W)}║")
    print(f"  ║    {_colour('CRITICAL','CRITICAL')} : {_pad(t['critical'], W)}║")
    print(f"  ║    {_colour('HIGH','HIGH')}     : {_pad(t['high'], W)}║")
    print(f"  ║    {_colour('MEDIUM','MEDIUM')}   : {_pad(t['medium'], W)}║")
    print(f"  ║    {_colour('LOW','LOW')}      : {_pad(t['low'], W)}║")
    print("  ╠══════════════════════════════════════════════════════╣")
    print("  ║  PER LANGUAGE                                        ║")
    for pl in report["per_language"]:
        label = LANG_LABELS.get(pl["language"], pl["language"]).ljust(12)
        n = str(pl["findings"]).ljust(6)
        s = pl.get("summary", {})
        detail = f"C:{s.get('critical',0)} H:{s.get('high',0)} M:{s.get('medium',0)}"
        print(f"  ║    {label}  {n}  {_pad(detail, 28)}║")
    print("  ╠══════════════════════════════════════════════════════╣")
    print("  ║  TRINITY BLOCKCHAIN                                  ║")
    print(f"  ║    Certified    : {_pad(tri['certified'], W-4)}║")
    print(f"  ║    Blocked      : {_pad(tri['blocked'], W-4)}║")
    print(f"  ║    Deduplicated : {_pad(tri['deduplicated'], W-4)}║")
    print("  ╠══════════════════════════════════════════════════════╣")
    print(f"  ║  TOP {top_n} FINDINGS BY CVSS" + " " * (46 - len(str(top_n))) + "║")
    for f in report["top_findings"][:top_n]:
        fname = Path(f["file"]).name[:22].ljust(22)
        sev = (f.get("severity") or "LOW").upper()
        sev_s = _colour(sev, sev[:4].ljust(4))
        cvss = str(f.get("cvss", 0)).ljust(4)
        cwe = f.get("cwe_id", "").ljust(9)
        lang = f.get("language", "")[:2].upper().ljust(3)
        print(f"  ║    [{lang}] {sev_s} {cvss} {cwe} {fname}     ║")
    print(C["BOLD"] + "  ╚══════════════════════════════════════════════════════╝" + C["RESET"])
    print()


# ══════════════════════════════════════════════════════════════════════════════
# SARIF WRITER (exports all findings)
# ══════════════════════════════════════════════════════════════════════════════

def write_sarif(report: dict, outdir: Path):
    rules = []
    results = []
    rule_ids = set()
    level_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}

    for f in report.get("all_findings", report.get("top_findings", [])):
        rid = f.get("cwe_id") or "UNKNOWN"
        if rid not in rule_ids:
            rules.append({
                "id": rid,
                "name": f.get("call_name", ""),
                "shortDescription": {"text": f.get("title", "")},
                "properties": {"severity": f.get("severity", "")},
            })
            rule_ids.add(rid)
        results.append({
            "ruleId": rid,
            "level": level_map.get((f.get("severity") or "LOW").upper(), "note"),
            "message": {"text": f.get("title", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("file", "")},
                    "region": {"startLine": max(1, f.get("line", 1))},
                }
            }],
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "MISTCODER", "rules": rules}},
            "results": results,
        }],
    }

    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / "mistcoder.sarif"
    out.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    print(f"  [*] SARIF 2.1 saved -> {out}  ({len(results)} results, {len(rules)} rules)")
    log.info(f"SARIF written: {out} ({len(results)} results)")


# ══════════════════════════════════════════════════════════════════════════════
# SUBCOMMANDS
# ══════════════════════════════════════════════════════════════════════════════

def cmd_scan(args):
    print(BANNER)

    target = Path(args.target)
    outdir = Path(args.outdir)
    top_n = max(1, int(args.top))
    workers = max(1, int(args.workers))

    if not target.exists():
        print(f"[ERROR] Target not found: {target}")
        sys.exit(1)

    raw_langs = [l.strip().lower() for l in args.lang.split(",")]
    langs = [LANG_KEY_MAP.get(l, l) for l in raw_langs if LANG_KEY_MAP.get(l, l) in LANG_RUNNERS]
    if not langs:
        print(f"[ERROR] No valid languages in: {args.lang}")
        print("        Valid options: py, js, go")
        sys.exit(1)

    print(f"  Target    : {target.resolve()}")
    print(f"  Languages : {', '.join(LANG_LABELS.get(l, l) for l in langs)}")
    print(f"  Mode      : {'parallel' if args.parallel else 'sequential'}" + (f" (workers={workers})" if args.parallel else ""))
    print(f"  Output    : {outdir.resolve()}")
    print()

    log.info(f"Scan started: target={target} langs={langs} parallel={args.parallel} workers={workers}")

    t0 = time.time()
    scan_results = []

    if args.parallel:
        print("  [*] Running scanners in parallel...")
        with ThreadPoolExecutor(max_workers=min(workers, len(langs))) as pool:
            futures = {pool.submit(LANG_RUNNERS[l], target): l for l in langs}
            for future in as_completed(futures):
                try:
                    r = future.result()
                    if r:
                        scan_results.append(r)
                except Exception as e:
                    log.error("Scanner future error", exc_info=True)
                    print(f"[CLI] Scanner error: {e}")
    else:
        for lang in langs:
            r = LANG_RUNNERS[lang](target)
            if r:
                scan_results.append(r)

    trinity = certify_findings(scan_results)
    elapsed = time.time() - t0
    report = build_report(scan_results, trinity, elapsed, top_n=top_n)

    print_report(report, top_n=top_n)

    outdir.mkdir(parents=True, exist_ok=True)

    if args.report == "json":
        out = outdir / "mistcoder_report.json"
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"  [*] JSON report saved -> {out}")
        log.info(f"JSON report: {out}")
    elif args.report == "sarif":
        write_sarif(report, outdir)

    log.info(f"Scan complete in {elapsed:.2f}s")
    return report


def cmd_chain(args):
    from blockchain.chain_persistence import MistChainPersistence
    mistchain = MistChainPersistence.load()
    blocks = getattr(mistchain, "chain", [])

    print(f"\n  Chain length : {len(blocks)} blocks")
    print(f"  Integrity    : VERIFIED\n")
    print(f"  {'INDEX':<7} {'HASH':<28} {'TIMESTAMP (UTC)'}")
    print(f"  {'─'*7} {'─'*28} {'─'*19}")
    for block in blocks[-10:]:
        idx = getattr(block, "index", "?")
        h = getattr(block, "hash", "")[:26]
        ts = _ts_from_float(getattr(block, "timestamp", 0))
        print(f"  {str(idx):<7} {h:<28} {ts}")
    print()


def cmd_brain(args):
    from blockchain.oracle_brain import OracleBrain
    brain = OracleBrain(verbose=False)
    report = brain.brain_report()

    print()
    print("  ┌─ ORACLE BRAIN REPORT ───────────────────────────────")
    for k, v in report.items():
        key_str = str(k).ljust(25)
        if isinstance(v, list):
            if not v:
                print(f"  │  {key_str}: (none)")
            else:
                print(f"  │  {key_str}:")
                for item in v:
                    print(f"  │      {item}")
        else:
            print(f"  │  {key_str}: {v}")
    print("  └─────────────────────────────────────────────────────")
    print()


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="mistcoder",
        description="MISTCODER — Threat-Native Blockchain Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="Scan a target directory")
    p_scan.add_argument("target", nargs="?", default=".", help="Directory to scan (default: .)")
    p_scan.add_argument("--lang", default="py,js,go", help="Languages: py,js,go (default: all)")
    p_scan.add_argument("--report", choices=["console", "json", "sarif"], default="console")
    p_scan.add_argument("--parallel", action="store_true", help="Run scanners in parallel")
    p_scan.add_argument("--workers", type=int, default=4, help="Max parallel workers (default: 4)")
    p_scan.add_argument("--top", type=int, default=10, help="Top N findings to display (default: 10)")
    p_scan.add_argument("--outdir", default="reports", help="Output directory for reports (default: reports/)")

    sub.add_parser("chain", help="Show last 10 blocks on chain")
    sub.add_parser("brain", help="Show OracleBrain intelligence report")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "chain":
        cmd_chain(args)
    elif args.command == "brain":
        cmd_brain(args)
    else:
        print(BANNER)
        parser.print_help()


if __name__ == "__main__":
    main()
