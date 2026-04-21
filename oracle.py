#!/usr/bin/env python3
"""
MISTCODER — ORACLE Engine
oracle.py  —  The CLI entry point.

Usage:
    python oracle.py <path>              Scan a file or directory
    python oracle.py <path> --json       Export JSON report
    python oracle.py <path> --quiet      Summary only, no per-file detail
    python oracle.py <path> --watch      Rescan on file change (dev mode)
    python oracle.py --self-test         Run against built-in vulnerable target

Zero external dependencies. Requires Python 3.8+.
"""
import argparse
import sys
import os
import time
from pathlib import Path

# ── Path setup: allow running from repo root or modules/ingestion/ ──────────
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE / "modules" / "ingestion" / "src"))
sys.path.insert(0, str(_HERE))

from python_ast_walker import analyse_file, analyse_directory
from oracle_report import render_full_report, print_banner, DIM, CYAN, GREEN, RED, BOLD


# ─────────────────────────────────────────────────────────────────────────────
# Built-in self-test target (deliberately vulnerable code snippet)
# ─────────────────────────────────────────────────────────────────────────────

SELF_TEST_CODE = '''
"""
MISTCODER self-test target.
This file is INTENTIONALLY VULNERABLE for testing purposes only.
It is never executed — only statically analysed.
"""
import os
import hashlib
import random
import subprocess
import pickle
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Hardcoded secret — deliberately exposed for self-test
SECRET_KEY = "sk_live_TEST_ORACLE_DETECTION_KEY_abc123xyz"
DB_PASSWORD = "hunter2_test_only_not_real"
AWS_KEY = "AKIATEST1234567890AB"

def login():
    # Weak hashing — MD5 password storage
    password = request.form.get("password")
    hashed = hashlib.md5(password.encode()).hexdigest()  # WEAK: MD5
    return hashed

def search_users():
    # SQL injection — unsanitized query parameter in SQL
    username = request.args.get("username")
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    db.execute(query)  # SINK: SQL with user input

def run_command():
    # OS command injection — attacker controls shell command
    cmd = request.args.get("cmd")
    result = os.system(cmd)  # CRITICAL: OS command with user input
    return result

def render_page():
    # Server-side template injection
    template = request.args.get("template")
    return render_template_string(template)  # CRITICAL: SSTI

def process_data():
    # Insecure deserialization
    data = request.data
    obj = pickle.loads(data)  # CRITICAL: pickle with network input
    return obj

def generate_token():
    # Insecure random — use secrets module instead
    token = str(random.random())  # WEAK: not cryptographically secure
    return token

def fetch_url(url):
    import requests
    # TLS verification disabled
    resp = requests.get(url, verify=False)  # CRITICAL: cert not verified
    return resp.text
'''


def _run_self_test(json_out: str = "") -> int:
    """Write the self-test target to a temp file and scan it."""
    import tempfile
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py",
        prefix="mistcoder_oracle_selftest_",
        delete=False,
        encoding="utf-8",
    ) as f:
        f.write(SELF_TEST_CODE)
        tmp_path = f.name

    try:
        t0 = time.perf_counter()
        result = analyse_file(tmp_path)
        elapsed = int((time.perf_counter() - t0) * 1000)
        render_full_report(
            [result],
            target=f"[SELF-TEST] {tmp_path}",
            elapsed_ms=elapsed,
            export_json=json_out,
        )
        total = result.finding_count
        expected_min = 5
        if total >= expected_min:
            print(GREEN(BOLD(f"  SELF-TEST PASSED — {total} findings detected (≥{expected_min} expected)\n")))
            return 0
        else:
            print(RED(BOLD(f"  SELF-TEST WARNING — only {total} findings (expected ≥{expected_min})\n")))
            return 1
    finally:
        os.unlink(tmp_path)


# ─────────────────────────────────────────────────────────────────────────────
# Watch mode
# ─────────────────────────────────────────────────────────────────────────────

def _watch_mode(target: str, json_out: str):
    """Re-scan whenever any .py file in target changes (dev mode)."""
    print(CYAN(BOLD(f"\n  ORACLE Watch Mode — monitoring {target}")))
    print(DIM("  Press Ctrl+C to exit\n"))

    def _get_mtimes(path: str) -> dict[str, float]:
        p = Path(path)
        if p.is_file():
            return {str(p): p.stat().st_mtime}
        return {str(f): f.stat().st_mtime for f in p.rglob("*.py")}

    last_mtimes = {}
    while True:
        try:
            current = _get_mtimes(target)
            if current != last_mtimes:
                if last_mtimes:  # not the first run
                    changed = [f for f, mt in current.items()
                               if mt != last_mtimes.get(f, 0)]
                    print(DIM(f"\n  Changed: {', '.join(os.path.basename(f) for f in changed[:3])}"))
                last_mtimes = current
                os.system("cls" if os.name == "nt" else "clear")
                _do_scan(target, json_out=json_out, quiet=False)
            time.sleep(1.5)
        except KeyboardInterrupt:
            print(DIM("\n  Watch mode stopped.\n"))
            break


# ─────────────────────────────────────────────────────────────────────────────
# Main scan runner
# ─────────────────────────────────────────────────────────────────────────────

def _do_scan(target: str, json_out: str = "", quiet: bool = False) -> int:
    path = Path(target)

    if not path.exists():
        print(RED(f"Error: path not found: {target}"))
        return 2

    t0 = time.perf_counter()

    if path.is_file():
        results = [analyse_file(str(path))]
    else:
        results = analyse_directory(str(path))

    elapsed = int((time.perf_counter() - t0) * 1000)

    render_full_report(
        results,
        target=target,
        elapsed_ms=elapsed,
        export_json=json_out,
    )

    # Exit code: 0 = clean, 1 = findings present, 2 = error
    total_critical = sum(1 for r in results for f in r.flows if f.severity == "CRITICAL")
    if total_critical > 0:
        return 1
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="oracle",
        description="MISTCODER ORACLE — Python Static Intelligence Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python oracle.py src/                      Scan entire src directory
  python oracle.py app.py                    Scan a single file
  python oracle.py src/ --json report.json   Scan + export JSON
  python oracle.py src/ --watch              Live rescan on change
  python oracle.py --self-test               Verify engine works correctly
        """,
    )
    parser.add_argument("target", nargs="?", help="File or directory to scan")
    parser.add_argument("--json",       metavar="FILE",  help="Export JSON report to FILE")
    parser.add_argument("--quiet",      action="store_true", help="Summary only")
    parser.add_argument("--watch",      action="store_true", help="Rescan on file change")
    parser.add_argument("--self-test",  action="store_true", help="Run built-in self-test")

    args = parser.parse_args()

    # Self-test mode
    if args.self_test:
        sys.exit(_run_self_test(json_out=args.json or ""))

    # Normal scan
    if not args.target:
        parser.print_help()
        sys.exit(0)

    if args.watch:
        _watch_mode(args.target, json_out=args.json or "")
        sys.exit(0)

    sys.exit(_do_scan(args.target, json_out=args.json or "", quiet=args.quiet))


if __name__ == "__main__":
    main()
