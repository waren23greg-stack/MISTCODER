"""
MISTCODER — ORACLE Engine
modules/ingestion/src/oracle_report.py

Terminal report renderer. Produces the full ORACLE intelligence report
with color, severity hierarchy, attack path summaries, and remediation
guidance. This is what operators see when they run a scan.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from taint_model import (
    FileAnalysisResult, TaintFlow, CryptoFinding, SecretFinding,
    SinkKind, CryptoIssueKind, SecretKind,
)


# ─────────────────────────────────────────────────────────────────────────────
# ANSI colour palette
# ─────────────────────────────────────────────────────────────────────────────

NO_COLOR = os.environ.get("NO_COLOR", "") != "" or not os.isatty(1)

def _c(code: str, text: str) -> str:
    return text if NO_COLOR else f"\033[{code}m{text}\033[0m"

def RED(t):      return _c("91", t)
def YELLOW(t):   return _c("93", t)
def GREEN(t):    return _c("92", t)
def CYAN(t):     return _c("96", t)
def BLUE(t):     return _c("94", t)
def MAGENTA(t):  return _c("95", t)
def BOLD(t):     return _c("1",  t)
def DIM(t):      return _c("2",  t)
def WHITE(t):    return _c("97", t)

SEV_COLOR = {
    "CRITICAL": RED,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      GREEN,
    "INFO":     DIM,
}

def sev(s: str) -> str:
    fn = SEV_COLOR.get(s, DIM)
    return fn(BOLD(f"[{s}]"))


# ─────────────────────────────────────────────────────────────────────────────
# Remediation library
# ─────────────────────────────────────────────────────────────────────────────

_REMEDIATION = {
    SinkKind.SQL_QUERY: (
        "Use parameterized queries. Never concatenate user input into SQL.",
        "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
    ),
    SinkKind.OS_COMMAND: (
        "Avoid shell=True. Use subprocess with a list of arguments. Whitelist inputs.",
        "subprocess.run(['ls', '-la', safe_dir], shell=False, check=True)",
    ),
    SinkKind.EVAL_EXEC: (
        "Never eval() user input. Use ast.literal_eval() for safe data parsing.",
        "import ast; value = ast.literal_eval(user_string)",
    ),
    SinkKind.FILE_PATH: (
        "Resolve and validate the final path is inside the allowed directory.",
        "safe = base.resolve(); assert str(path.resolve()).startswith(str(safe))",
    ),
    SinkKind.TEMPLATE_RENDER: (
        "Never use render_template_string() with user input. Use static templates.",
        "return render_template('page.html', name=escape(user_name))",
    ),
    SinkKind.PICKLE_LOAD: (
        "Never unpickle untrusted data. Use JSON or msgpack for data exchange.",
        "data = json.loads(user_bytes)  # safe alternative",
    ),
    SinkKind.REDIRECT: (
        "Validate redirect targets against an explicit allowlist of safe URLs.",
        "if url not in ALLOWED_REDIRECTS: abort(400)",
    ),
    SinkKind.HTML_OUTPUT: (
        "Use Jinja2 autoescaping. Never use Markup() on user-controlled strings.",
        "# In Jinja2, autoescaping is on by default — don't disable it",
    ),
    SinkKind.DESERIALIZE: (
        "Use yaml.safe_load() instead of yaml.load(). Never deserialize untrusted data.",
        "data = yaml.safe_load(user_input)  # safe_load restricts to basic types",
    ),
}

_CRYPTO_REMEDIATION = {
    CryptoIssueKind.WEAK_HASH: (
        "Use SHA-256 or SHA-3 for non-password hashing. Use bcrypt/argon2 for passwords.",
        "import hashlib; h = hashlib.sha256(data).hexdigest()",
    ),
    CryptoIssueKind.WEAK_CIPHER: (
        "Use AES-256-GCM (authenticated encryption). Never use ECB mode.",
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM",
    ),
    CryptoIssueKind.INSECURE_RANDOM: (
        "Use the `secrets` module for all security-sensitive random generation.",
        "import secrets; token = secrets.token_hex(32)",
    ),
    CryptoIssueKind.NO_CERT_VERIFY: (
        "Never disable TLS verification in production. Use proper CA bundles.",
        "requests.get(url, verify='/path/to/ca-bundle.crt')",
    ),
    CryptoIssueKind.HARDCODED_KEY: (
        "Load keys from environment variables or a secrets manager at runtime.",
        "SECRET_KEY = os.environ['SECRET_KEY']  # never hardcode",
    ),
}

_SECRET_REMEDIATION = {
    SecretKind.API_KEY: (
        "Move to environment variable or secrets manager. Rotate the exposed key immediately.",
        "api_key = os.environ.get('API_KEY')  # or use Vault/AWS Secrets Manager",
    ),
    SecretKind.PRIVATE_KEY: (
        "IMMEDIATELY rotate this key. Store private keys in HSM or secrets manager only.",
        "# Load from file outside repo: key = open('/run/secrets/privkey.pem').read()",
    ),
    SecretKind.PASSWORD: (
        "Move to environment variable. Never hardcode credentials in source.",
        "DB_PASS = os.environ['DB_PASSWORD']",
    ),
    SecretKind.CONNECTION_STRING: (
        "Move database URLs to environment variables. Check git history for exposure.",
        "DATABASE_URL = os.environ['DATABASE_URL']",
    ),
    SecretKind.JWT_SECRET: (
        "Generate a cryptographically strong secret. Load from environment, never hardcode.",
        "JWT_SECRET = os.environ['JWT_SECRET']  # min 32 bytes of entropy",
    ),
    SecretKind.OAUTH_SECRET: (
        "Rotate OAuth credentials immediately. Store in secrets manager.",
        "CLIENT_SECRET = os.environ['OAUTH_CLIENT_SECRET']",
    ),
    SecretKind.GENERIC_HIGH_ENTROPY: (
        "Verify this is not a real credential. If it is, rotate and move to env.",
        "# Move to: VALUE = os.environ['VALUE']",
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Report building
# ─────────────────────────────────────────────────────────────────────────────

def _divider(char: str = "─", width: int = 72) -> str:
    return DIM(char * width)

def _header(title: str, width: int = 72) -> str:
    return (
        f"\n{_divider('═', width)}\n"
        f"  {BOLD(WHITE(title))}\n"
        f"{_divider('═', width)}"
    )

def _section(title: str) -> str:
    return f"\n{_divider()}\n  {BOLD(CYAN(title))}\n{_divider()}"


def print_banner():
    print(CYAN(BOLD(r"""
███╗   ███╗██╗███████╗████████╗ ██████╗ ██████╗ ██████╗ ███████╗██████╗
████╗ ████║██║██╔════╝╚══██╔══╝██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗
██╔████╔██║██║███████╗   ██║   ██║     ██║   ██║██║  ██║█████╗  ██████╔╝
██║╚██╔╝██║██║╚════██║   ██║   ██║     ██║   ██║██║  ██║██╔══╝  ██╔══██╗
██║ ╚═╝ ██║██║███████║   ██║   ╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║
╚═╝     ╚═╝╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝""")))
    print(DIM("  ORACLE Engine — Static Intelligence Core  │  Phase 2 Prototype\n"))


def render_flow(flow: TaintFlow, idx: int):
    rem = _REMEDIATION.get(flow.sink.kind)
    print(f"\n  {sev(flow.severity)} {BOLD(flow.title())}  {DIM(flow.cwe())}")
    print(f"    {DIM('Source:')} {CYAN(flow.source.kind.value)}"
          f"  {DIM('at')}  {flow.source.location}")
    print(f"    {DIM('Sink  :')} {RED(flow.sink.kind.value)}"
          f"  {DIM('at')}  {flow.sink.location}")
    print(f"    {DIM('Expr  :')} {DIM(flow.sink.expression[:80])}")
    if flow.sanitized:
        print(f"    {GREEN('⚑ Sanitizer detected — may be mitigated')}")
    if rem:
        guidance, example = rem
        print(f"    {DIM('Fix   :')} {guidance}")
        print(f"    {DIM('Code  :')} {GREEN(example)}")


def render_crypto(c: CryptoFinding, idx: int):
    rem = _CRYPTO_REMEDIATION.get(c.kind, ("Review this usage.", ""))
    print(f"\n  {sev(c.severity)} {BOLD(c.kind.value.replace('_', ' ').title())}")
    print(f"    {DIM('At    :')} {c.location}")
    print(f"    {DIM('Expr  :')} {DIM(c.expression[:80])}")
    if c.detail:
        print(f"    {DIM('Detail:')} {c.detail}")
    print(f"    {DIM('Fix   :')} {rem[0]}")
    if rem[1]:
        print(f"    {DIM('Code  :')} {GREEN(rem[1])}")


def render_secret(s: SecretFinding, idx: int):
    rem = _SECRET_REMEDIATION.get(s.kind, ("Move to environment variable.", ""))
    print(f"\n  {sev(s.severity)} {BOLD(s.kind.value.replace('_', ' ').title())}")
    print(f"    {DIM('At      :')} {s.location}")
    print(f"    {DIM('Pattern :')} {s.pattern}")
    print(f"    {DIM('Preview :')} {RED(s.value)}")
    print(f"    {DIM('Entropy :')} {s.entropy:.2f} bits")
    print(f"    {DIM('Action  :')} {YELLOW(rem[0])}")


def render_file_result(result: FileAnalysisResult, verbose: bool = True):
    if result.parse_error:
        print(f"  {YELLOW('⚠')} {DIM(result.path)} — parse error: {result.parse_error}")
        return
    if result.finding_count == 0:
        if verbose:
            print(f"  {GREEN('✓')} {DIM(result.path)} — no findings")
        return

    print(f"\n  {BOLD(MAGENTA(result.path))}")
    print(f"  {DIM(f'Functions: {len(result.functions)}  |  Sources: {len(result.sources)}  |  Sinks: {len(result.sinks)}  |  Flows: {len(result.flows)}  |  Crypto: {len(result.crypto)}  |  Secrets: {len(result.secrets)}')}")

    if result.flows:
        print(f"\n  {BOLD('Taint Flows')}")
        for i, flow in enumerate(sorted(result.flows, key=lambda f: ["CRITICAL","HIGH","MEDIUM","LOW"].index(f.severity)), 1):
            render_flow(flow, i)

    if result.crypto:
        print(f"\n  {BOLD('Cryptographic Issues')}")
        for i, c in enumerate(result.crypto, 1):
            render_crypto(c, i)

    if result.secrets:
        print(f"\n  {BOLD('Exposed Secrets')}")
        for i, s in enumerate(result.secrets, 1):
            render_secret(s, i)


def render_full_report(
    results:    list[FileAnalysisResult],
    target:     str,
    elapsed_ms: int,
    export_json: str = "",
):
    print_banner()

    # ── Aggregate stats ──────────────────────────────────────────────
    total_flows    = sum(len(r.flows)   for r in results)
    total_crypto   = sum(len(r.crypto)  for r in results)
    total_secrets  = sum(len(r.secrets) for r in results)
    total_functions= sum(len(r.functions) for r in results)
    total_files    = len(results)
    files_clean    = sum(1 for r in results if r.finding_count == 0)
    files_errors   = sum(1 for r in results if r.parse_error)

    critical = sum(1 for r in results for f in r.flows if f.severity == "CRITICAL")
    high     = sum(1 for r in results for f in r.flows if f.severity == "HIGH")
    medium   = sum(1 for r in results for f in r.flows if f.severity == "MEDIUM")

    print(_header("ORACLE INTELLIGENCE REPORT"))
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"  {DIM('Target   :')} {CYAN(target)}")
    print(f"  {DIM('Timestamp:')} {ts}")
    print(f"  {DIM('Engine   :')} ORACLE v1.0 — Python AST Walker + Taint Engine")
    print(f"  {DIM('Duration :')} {elapsed_ms}ms")

    # ── Summary matrix ───────────────────────────────────────────────
    print(_section("SCAN SUMMARY"))
    print(f"  {DIM('Files scanned :')} {total_files}  ({files_clean} clean, {files_errors} errors)")
    print(f"  {DIM('Functions     :')} {total_functions}")
    print(f"  {DIM('Taint flows   :')} {total_flows}")
    print(f"  {DIM('Crypto issues :')} {total_crypto}")
    print(f"  {DIM('Secrets found :')} {total_secrets}")

    print()
    if critical:
        print(f"  {RED(BOLD(f'● CRITICAL  {critical}'))}  {'█' * min(critical, 40)}")
    if high:
        print(f"  {RED(f'● HIGH      {high}')}  {'█' * min(high, 40)}")
    if medium:
        print(f"  {YELLOW(f'● MEDIUM    {medium}')}  {'█' * min(medium, 40)}")

    # ── Top attack surfaces ──────────────────────────────────────────
    if total_flows > 0:
        print(_section("CRITICAL ATTACK SURFACES"))
        crit_flows = [
            (r.path, f)
            for r in results
            for f in r.flows
            if f.severity in ("CRITICAL", "HIGH")
        ]
        crit_flows.sort(key=lambda x: ["CRITICAL","HIGH"].index(x[1].severity))
        for path, flow in crit_flows[:8]:
            fname = os.path.basename(path)
            print(f"  {sev(flow.severity)}  {BOLD(flow.title()):<40}  "
                  f"{DIM(fname)}:{flow.sink.location.line}  {DIM(flow.cwe())}")

    # ── File-by-file detail ──────────────────────────────────────────
    files_with_findings = [r for r in results if r.finding_count > 0]
    if files_with_findings:
        print(_section(f"FILE DETAILS  ({len(files_with_findings)} files with findings)"))
        for result in files_with_findings:
            render_file_result(result, verbose=False)

    # ── Risk verdict ─────────────────────────────────────────────────
    print(_section("RISK VERDICT"))
    if critical >= 3:
        verdict = RED(BOLD("CRITICAL RISK — Immediate action required"))
        rec     = RED("Stop deployment. Remediate CRITICAL findings before any release.")
    elif critical >= 1:
        verdict = RED(BOLD("HIGH RISK — Critical vulnerabilities present"))
        rec     = YELLOW("Address all CRITICAL findings before production deployment.")
    elif high >= 3:
        verdict = YELLOW(BOLD("ELEVATED RISK — Multiple high-severity findings"))
        rec     = YELLOW("Plan remediation sprint. Do not deploy to internet-facing systems.")
    elif high >= 1 or medium >= 3:
        verdict = YELLOW(BOLD("MODERATE RISK — Findings require attention"))
        rec     = GREEN("Prioritize HIGH findings. Track MEDIUM in backlog.")
    else:
        verdict = GREEN(BOLD("LOW RISK — No critical or high findings detected"))
        rec     = GREEN("Continue standard security review cadence.")

    print(f"\n  {verdict}")
    print(f"  {rec}\n")

    # ── JSON export ──────────────────────────────────────────────────
    if export_json:
        _export_json(results, target, ts, export_json)
        print(f"  {DIM('JSON report  →')} {GREEN(export_json)}")

    print(_divider("═"))
    print(f"  {DIM('MISTCODER ORACLE — Phase 2 prototype')}"
          f"  {DIM('│')}  {DIM('Feed findings to: modules/knowledge_graph/')}\n")


def _export_json(
    results:    list[FileAnalysisResult],
    target:     str,
    timestamp:  str,
    path:       str,
):
    payload: dict[str, Any] = {
        "mistcoder_version": "0.2.0-oracle",
        "engine": "ORACLE",
        "target": target,
        "timestamp": timestamp,
        "summary": {
            "files":   len(results),
            "flows":   sum(len(r.flows)  for r in results),
            "crypto":  sum(len(r.crypto) for r in results),
            "secrets": sum(len(r.secrets)for r in results),
        },
        "files": [],
    }

    for r in results:
        if r.parse_error or r.finding_count == 0:
            continue
        file_entry: dict[str, Any] = {
            "path": r.path,
            "taint_flows": [
                {
                    "severity":  f.severity,
                    "cwe":       f.cwe(),
                    "source_kind": f.source.kind.value,
                    "sink_kind":   f.sink.kind.value,
                    "source_loc":  str(f.source.location),
                    "sink_loc":    str(f.sink.location),
                    "sanitized":   f.sanitized,
                    "confidence":  f.confidence,
                }
                for f in r.flows
            ],
            "crypto_findings": [
                {
                    "severity": c.severity,
                    "kind":     c.kind.value,
                    "location": str(c.location),
                    "detail":   c.detail,
                }
                for c in r.crypto
            ],
            "secrets": [
                {
                    "severity": s.severity,
                    "kind":     s.kind.value,
                    "location": str(s.location),
                    "entropy":  round(s.entropy, 3),
                    "pattern":  s.pattern,
                }
                for s in r.secrets
            ],
        }
        payload["files"].append(file_entry)

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
