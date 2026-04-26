# blockchain/lang/lang_bridge.py
# MISTCODER Layer 9 — Multi-Language Trinity Bridge
#
# Takes findings from JS or Go scanner,
# groups them into kill chains by co-occurrence,
# and feeds every chain through the full Trinity pipeline.
#
# Usage:
#   python -m blockchain.lang.lang_bridge --js  path/to/js/code
#   python -m blockchain.lang.lang_bridge --go  path/to/go/code
#   python -m blockchain.lang.lang_bridge --all path/to/mixed/repo

import sys
import json
from pathlib import Path
from datetime import datetime, timezone
from blockchain.phantom_chain_bridge import PhantomChainBridge
from blockchain.chain_persistence import MistChainPersistence

SEVERITY_STEALTH = {
    "CRITICAL": 0.92, "HIGH": 0.75,
    "MEDIUM"  : 0.55, "LOW" : 0.30
}


def findings_to_kill_chains(findings: list, language: str) -> list:
    """
    Group raw findings into kill chains by file.
    Each file with 2+ findings becomes one kill chain.
    Single findings become solo chains.
    """
    from collections import defaultdict
    by_file = defaultdict(list)
    for f in findings:
        by_file[f["file"]].append(f)

    chains = []
    chain_num = 1
    for filepath, file_findings in by_file.items():
        # Deduplicate by cwe_id within file
        seen_cwes = set()
        nodes     = []
        for f in file_findings:
            if f["cwe_id"] not in seen_cwes:
                nodes.append(f)
                seen_cwes.add(f["cwe_id"])

        if not nodes:
            continue

        # Score = average CVSS across nodes
        score   = round(
            sum(n["cvss_score"] for n in nodes) / len(nodes), 2
        )
        stealth = round(
            sum(SEVERITY_STEALTH.get(n["severity"].upper(), 0.55)
                for n in nodes) / len(nodes), 2
        )

        chains.append({
            "path_id" : f"LANG-{language.upper()[:2]}-{chain_num:04d}",
            "language": language,
            "file"    : filepath,
            "nodes"   : nodes,
            "score"   : score,
            "stealth" : stealth,
            "novelty" : 0.5
        })
        chain_num += 1

    return chains


def run_language_scan(target: str, language: str) -> dict:
    """
    Full scan pipeline for a single language.
    Scan → group into chains → Trinity deliberation → chain commit.
    """
    target_path = Path(target)
    print(f"\n[LANG BRIDGE] ═══ {language.upper()} SCAN ═══")
    print(f"[LANG BRIDGE] Target: {target_path}")
    print()

    # ── Scan ──────────────────────────────────────────────────────────────
    if language == "javascript":
        from blockchain.lang.js_scanner import JSScanner
        scanner = JSScanner()
        report  = scanner.scan_directory(target_path)
    elif language == "go":
        from blockchain.lang.go_scanner import GoScanner
        scanner = GoScanner()
        report  = scanner.scan_directory(target_path)
    else:
        print(f"[LANG BRIDGE] Unknown language: {language}")
        return {}

    findings = report.get("findings", [])
    if not findings:
        print(f"[LANG BRIDGE] No findings in {language} scan.")
        return report

    # ── Group into kill chains ────────────────────────────────────────────
    chains = findings_to_kill_chains(findings, language)
    print(f"[LANG BRIDGE] {len(findings)} findings → {len(chains)} kill chains")
    print()

    # ── Load persisted chain ──────────────────────────────────────────────
    print("[PERSIST] Loading chain from disk...")
    loaded_chain = MistChainPersistence.load()

    bridge       = PhantomChainBridge(node_id=f"NODE-{language.upper()[:2]}")
    bridge.chain = loaded_chain

    # ── Feed each kill chain through Trinity ──────────────────────────────
    results = {"certified": [], "blocked": [], "deduplicated": []}

    for chain in chains:
        finding_id = chain["path_id"]

        # Deduplication check
        existing = MistChainPersistence.lookup(finding_id)
        if existing:
            print(f"[DEDUP] ⟳ {finding_id} already certified in "
                  f"block {existing['block']}")
            results["deduplicated"].append(finding_id)
            continue

        # Extract steps
        steps = []
        seen  = set()
        for node in chain["nodes"]:
            for key in ("call_name", "cwe_id"):
                val = node.get(key, "")
                if val and val not in seen:
                    steps.append(val)
                    seen.add(val)

        block = bridge.phantom_submit(
            finding_id=finding_id,
            steps=steps,
            score=chain["score"],
            stealth=chain["stealth"],
            novelty=chain["novelty"]
        )

        if block:
            results["certified"].append({
                "finding_id": finding_id,
                "block"     : block.index,
                "hash"      : block.hash[:24],
                "score"     : chain["score"],
                "language"  : language,
                "file"      : chain["file"]
            })
        else:
            results["blocked"].append(finding_id)

    # ── Save chain ────────────────────────────────────────────────────────
    if results["certified"]:
        MistChainPersistence.save(bridge.chain)

    # ── Report ────────────────────────────────────────────────────────────
    print()
    print("═" * 60)
    print(f"  {language.upper()} SCAN — TRINITY RESULTS")
    print("═" * 60)
    print(f"  Findings     : {len(findings)}")
    print(f"  Kill chains  : {len(chains)}")
    print(f"  ✓ Certified  : {len(results['certified'])}")
    print(f"  ✗ Blocked    : {len(results['blocked'])}")
    print(f"  ⟳ Deduped   : {len(results['deduplicated'])}")
    print()
    for r in results["certified"]:
        print(f"  Block {r['block']} | {r['finding_id']} | "
              f"score={r['score']} | {Path(r['file']).name}")
    print("═" * 60)

    return {**report, "trinity_results": results}


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print("""
MISTCODER Multi-Language Scanner

  python -m blockchain.lang.lang_bridge --js  <path>   JavaScript scan
  python -m blockchain.lang.lang_bridge --go  <path>   Go scan
  python -m blockchain.lang.lang_bridge --all <path>   All languages
        """)
        sys.exit(0)

    flag   = args[0]
    target = args[1] if len(args) > 1 else "."

    if flag == "--js":
        run_language_scan(target, "javascript")
    elif flag == "--go":
        run_language_scan(target, "go")
    elif flag == "--all":
        run_language_scan(target, "javascript")
        run_language_scan(target, "go")
    else:
        print(f"Unknown flag: {flag}")
        sys.exit(1)