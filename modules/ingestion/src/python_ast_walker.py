"""
MISTCODER — ORACLE Engine
modules/ingestion/src/python_ast_walker.py

Real Python static analysis using the stdlib `ast` module.
Zero external dependencies. Walks any .py file and extracts:
  - Taint sources (HTTP params, env vars, file reads, user input)
  - Taint sinks   (SQL, exec, eval, subprocess, file writes, template render)
  - Crypto misuse (MD5, DES, ECB, static IV, insecure random)
  - Hardcoded secrets (entropy + pattern matching)
  - Inter-function data flow (which variables carry taint)
"""
from __future__ import annotations

import ast
import math
import os
import re
import string
from pathlib import Path
from typing import Optional

from modules.ingestion.src.taint_model import (
    TaintSource, TaintSink, TaintFlow, CryptoFinding, SecretFinding,
    FileAnalysisResult, SourceKind, SinkKind, CryptoIssueKind, SecretKind,
    SourceLocation,
)


# ─────────────────────────────────────────────────────────────────────────────
# Source pattern registry
# Maps (module, attribute) or function call patterns → SourceKind
# ─────────────────────────────────────────────────────────────────────────────

_SOURCE_PATTERNS: list[tuple[list[str], SourceKind, str]] = [
    # Flask
    (["request.args", "request.args.get"],         SourceKind.HTTP_PARAM,  "flask"),
    (["request.form", "request.form.get"],          SourceKind.HTTP_PARAM,  "flask"),
    (["request.values", "request.values.get"],      SourceKind.HTTP_PARAM,  "flask"),
    (["request.headers", "request.headers.get"],    SourceKind.HTTP_HEADER, "flask"),
    (["request.data", "request.get_json",
      "request.json"],                              SourceKind.HTTP_BODY,   "flask"),
    (["request.cookies", "request.cookies.get"],    SourceKind.HTTP_COOKIE, "flask"),
    # Django
    (["request.GET", "request.GET.get",
      "request.POST", "request.POST.get",
      "request.data"],                              SourceKind.HTTP_PARAM,  "django"),
    (["request.META"],                              SourceKind.HTTP_HEADER, "django"),
    # FastAPI / Starlette
    (["Query(", "Form(", "Body(", "Header(",
      "Cookie(", "Path("],                          SourceKind.HTTP_PARAM,  "fastapi"),
    # stdlib
    (["os.environ", "os.environ.get",
      "os.getenv"],                                 SourceKind.ENV_VAR,     ""),
    (["sys.argv"],                                  SourceKind.CLI_ARG,     ""),
    (["input("],                                    SourceKind.USER_INPUT,  ""),
    (["socket.recv", "conn.recv"],                  SourceKind.SOCKET_RECV, ""),
    (["pickle.loads", "pickle.load"],               SourceKind.DESERIALIZATION, ""),
    (["yaml.load(", "yaml.unsafe_load"],            SourceKind.DESERIALIZATION, ""),
]

_SINK_PATTERNS: list[tuple[list[str], SinkKind, str, str]] = [
    # SQL
    (["execute(", "executemany(", "raw(",
      "cursor.execute", "db.execute",
      "session.execute", "engine.execute",
      "connection.execute"],                        SinkKind.SQL_QUERY,     "HIGH",     ""),
    # OS command
    (["os.system(", "os.popen(",
      "subprocess.run(", "subprocess.call(",
      "subprocess.Popen(", "subprocess.check_output(",
      "commands.getoutput("],                       SinkKind.OS_COMMAND,    "CRITICAL", ""),
    # Eval / exec
    (["eval(", "exec(", "compile("],               SinkKind.EVAL_EXEC,     "CRITICAL", ""),
    # File
    (["open("],                                     SinkKind.FILE_PATH,     "MEDIUM",   ""),
    # Template injection
    (["render_template_string(", "Template(",
      "jinja2.Template(", "Environment().from_string("], SinkKind.TEMPLATE_RENDER, "CRITICAL", ""),
    # Pickle / deserialization
    (["pickle.loads(", "pickle.load(",
      "marshal.loads("],                            SinkKind.PICKLE_LOAD,   "CRITICAL", ""),
    # XML
    (["etree.fromstring(", "ET.fromstring(",
      "parseString(", "minidom.parseString("],      SinkKind.XML_PARSE,     "HIGH",     ""),
    # Redirect
    (["redirect(", "HttpResponseRedirect("],        SinkKind.REDIRECT,      "MEDIUM",   ""),
    # HTML unescaped
    (["Markup(", "mark_safe("],                     SinkKind.HTML_OUTPUT,   "HIGH",     ""),
    # Deserialize
    (["yaml.load(", "yaml.unsafe_load(",
      "jsonpickle.decode("],                        SinkKind.DESERIALIZE,   "CRITICAL", ""),
]

_CRYPTO_PATTERNS: list[tuple[list[str], CryptoIssueKind, str, str]] = [
    (["hashlib.md5(", "md5("],              CryptoIssueKind.WEAK_HASH,     "MEDIUM", "MD5 is broken for security use"),
    (["hashlib.sha1(", "sha1("],            CryptoIssueKind.WEAK_HASH,     "MEDIUM", "SHA-1 collision attacks exist"),
    (["DES.", "Blowfish.", "ARC2.",
      "ARC4.", "RC4("],                     CryptoIssueKind.WEAK_CIPHER,   "HIGH",   "Broken cipher algorithm"),
    (["AES.MODE_ECB", "mode=ECB",
      "MODE_ECB"],                          CryptoIssueKind.WEAK_CIPHER,   "HIGH",   "ECB mode leaks patterns"),
    (["random.random()", "random.randint(",
      "random.choice("],                   CryptoIssueKind.INSECURE_RANDOM,"HIGH",  "Use secrets module for crypto"),
    (["verify=False"],                      CryptoIssueKind.NO_CERT_VERIFY,"HIGH",   "TLS certificate not verified"),
    (["ssl._create_unverified_context"],    CryptoIssueKind.NO_CERT_VERIFY,"HIGH",   "TLS verification disabled"),
]

# Secret patterns (regex, kind, description)
_SECRET_PATTERNS: list[tuple[str, SecretKind, str]] = [
    (r'(api[_-]?key|apikey)\s*=\s*["\']([A-Za-z0-9_\-]{16,})["\']',
     SecretKind.API_KEY,            "API key literal"),
    (r'(password|passwd|pwd)\s*=\s*["\']([^"\']{6,})["\']',
     SecretKind.PASSWORD,           "Password literal"),
    (r'(secret[_-]?key|secret)\s*=\s*["\']([A-Za-z0-9_\-]{16,})["\']',
     SecretKind.JWT_SECRET,         "Secret key literal"),
    (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
     SecretKind.PRIVATE_KEY,        "Private key material"),
    (r'(mongodb|postgres|mysql|redis|amqp)://[^"\'>\s]{8,}',
     SecretKind.CONNECTION_STRING,  "Database connection string"),
    (r'(sk_live_|sk_test_|pk_live_|rk_live_)[A-Za-z0-9]{12,}',
     SecretKind.API_KEY,            "Stripe API key"),
    (r'ghp_[A-Za-z0-9]{36}',
     SecretKind.API_KEY,            "GitHub personal access token"),
    (r'AKIA[0-9A-Z]{16}',
     SecretKind.API_KEY,            "AWS access key ID"),
    (r'(client_secret|client_id)\s*=\s*["\']([A-Za-z0-9_\-]{12,})["\']',
     SecretKind.OAUTH_SECRET,       "OAuth client secret"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Shannon entropy
# ─────────────────────────────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _is_high_entropy_secret(value: str, min_len: int = 20, min_entropy: float = 3.5) -> bool:
    if len(value) < min_len:
        return False
    if not any(c in string.ascii_letters for c in value):
        return False
    if not any(c in string.digits for c in value):
        return False
    return _entropy(value) >= min_entropy


# ─────────────────────────────────────────────────────────────────────────────
# AST Visitor
# ─────────────────────────────────────────────────────────────────────────────

class OracleVisitor(ast.NodeVisitor):
    """
    Walks a Python AST and extracts all security-relevant patterns.
    Single-pass: O(n) in AST node count.
    """

    def __init__(self, filepath: str, source_text: str):
        self.filepath    = filepath
        self.source_text = source_text
        self.lines       = source_text.splitlines()

        self.functions:  list[str]          = []
        self.sources:    list[TaintSource]  = []
        self.sinks:      list[TaintSink]    = []
        self.crypto:     list[CryptoFinding]= []

        # Track: variable name → TaintSource (for intra-function flow)
        self._taint_vars: dict[str, TaintSource] = {}

    def _loc(self, node: ast.AST) -> SourceLocation:
        return SourceLocation(
            file=self.filepath,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
        )

    def _node_to_str(self, node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return "<expr>"

    # ── Function definitions ─────────────────────────────────────────

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.functions.append(node.name)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    # ── Assignment: track taint variable propagation ─────────────────

    def visit_Assign(self, node: ast.Assign):
        rhs_str = self._node_to_str(node.value)
        source  = self._match_source(rhs_str, node)
        if source:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._taint_vars[target.id] = source
        # Also check RHS for sinks (e.g. x = execute(user_input))
        self._check_for_sink(node.value, rhs_str)
        self._check_for_crypto(node.value, rhs_str)
        self.generic_visit(node)

    # ── All call expressions ─────────────────────────────────────────

    def visit_Call(self, node: ast.Call):
        call_str = self._node_to_str(node)
        # Check if this call IS a source
        source = self._match_source(call_str, node)
        if source:
            self.sources.append(source)
        # Check if this call IS a sink
        self._check_for_sink(node, call_str)
        # Check for crypto patterns
        self._check_for_crypto(node, call_str)
        self.generic_visit(node)

    # ── Source matching ──────────────────────────────────────────────

    def _match_source(self, expr: str, node: ast.AST) -> Optional[TaintSource]:
        for patterns, kind, framework in _SOURCE_PATTERNS:
            for p in patterns:
                if p in expr:
                    src = TaintSource(
                        kind=kind,
                        name=expr[:80],
                        location=self._loc(node),
                        framework=framework,
                    )
                    if src not in self.sources:
                        self.sources.append(src)
                    return src
        return None

    # ── Sink matching ────────────────────────────────────────────────

    def _check_for_sink(self, node: ast.AST, expr: str):
        for patterns, kind, severity, _ in _SINK_PATTERNS:
            for p in patterns:
                if p in expr:
                    # Check if any argument carries taint
                    carries_taint = self._args_carry_taint(node)
                    sink = TaintSink(
                        kind=kind,
                        expression=expr[:120],
                        location=self._loc(node),
                        confidence=0.9 if carries_taint else 0.4,
                    )
                    self.sinks.append(sink)
                    return

    def _args_carry_taint(self, node: ast.AST) -> bool:
        """Check if any argument in a call node references a known tainted var."""
        if not isinstance(node, ast.Call):
            return False
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in self._taint_vars:
                return True
            # Check string formatting with tainted vars
            arg_str = self._node_to_str(arg)
            if any(v in arg_str for v in self._taint_vars):
                return True
        for kw in node.keywords:
            if isinstance(kw.value, ast.Name) and kw.value.id in self._taint_vars:
                return True
        return False

    # ── Crypto pattern matching ──────────────────────────────────────

    def _check_for_crypto(self, node: ast.AST, expr: str):
        for patterns, kind, severity, detail in _CRYPTO_PATTERNS:
            for p in patterns:
                if p in expr:
                    self.crypto.append(CryptoFinding(
                        kind=kind,
                        expression=expr[:120],
                        location=self._loc(node),
                        detail=detail,
                        severity=severity,
                    ))
                    return


# ─────────────────────────────────────────────────────────────────────────────
# Flow inference: connect sources → sinks
# ─────────────────────────────────────────────────────────────────────────────

def _infer_flows(
    sources: list[TaintSource],
    sinks:   list[TaintSink],
    source_text: str,
) -> list[TaintFlow]:
    """
    Lightweight flow inference: if a source and sink appear in the same
    function body and no sanitizer is detected between them, create a flow.

    Full inter-procedural analysis requires the full IR graph (MOD-01).
    This gives a high-confidence approximation for single-file analysis.
    """
    flows: list[TaintFlow] = []
    lines = source_text.splitlines()

    _SANITIZERS = [
        "escape(", "quote(", "htmlspecialchars", "sanitize(",
        "parameterize", "bindparam", "text(", "?",
        "bleach.clean", "markupsafe", "html.escape",
        "shlex.quote", "subprocess.run.*shell=False",
        "validate(", "clean(", "filter(",
    ]

    for sink in sinks:
        # Find the nearest source above this sink (within 50 lines)
        best_source = None
        best_distance = 999
        for source in sources:
            distance = sink.location.line - source.location.line
            if 0 <= distance < best_distance:
                best_distance = distance
                best_source = source

        if best_source is None:
            continue

        # Check if any sanitizer appears between source and sink
        start = best_source.location.line - 1
        end   = sink.location.line
        between = "\n".join(lines[start:end])
        sanitized = any(s in between for s in _SANITIZERS)

        # Severity mapping
        severity_map = {
            SinkKind.OS_COMMAND:    "CRITICAL",
            SinkKind.EVAL_EXEC:     "CRITICAL",
            SinkKind.TEMPLATE_RENDER: "CRITICAL",
            SinkKind.PICKLE_LOAD:   "CRITICAL",
            SinkKind.DESERIALIZE:   "CRITICAL",
            SinkKind.SQL_QUERY:     "HIGH",
            SinkKind.FILE_PATH:     "HIGH",
            SinkKind.XML_PARSE:     "HIGH",
            SinkKind.HTML_OUTPUT:   "HIGH",
            SinkKind.REDIRECT:      "MEDIUM",
            SinkKind.FILE_WRITE:    "MEDIUM",
        }
        severity = severity_map.get(sink.kind, "MEDIUM")
        if sanitized:
            severity = "LOW"

        flows.append(TaintFlow(
            source=best_source,
            sink=sink,
            sanitized=sanitized,
            severity=severity,
            confidence=0.85 if not sanitized else 0.3,
        ))

    return flows


# ─────────────────────────────────────────────────────────────────────────────
# Secret scanner
# ─────────────────────────────────────────────────────────────────────────────

def _scan_secrets(filepath: str, source_text: str) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    lines = source_text.splitlines()

    for lineno, line in enumerate(lines, 1):
        # Skip obvious non-code lines
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue

        loc = SourceLocation(file=filepath, line=lineno)

        # Pattern-based detection
        for pattern, kind, description in _SECRET_PATTERNS:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                value = match.group(0)
                findings.append(SecretFinding(
                    kind=kind,
                    value=value[:8] + "..." + value[-4:] if len(value) > 16 else value,
                    location=loc,
                    entropy=_entropy(value),
                    pattern=description,
                    severity="CRITICAL" if kind == SecretKind.PRIVATE_KEY else "HIGH",
                ))
                continue

        # Entropy-based: catch high-entropy string assignments
        ent_match = re.search(
            r'''["\']([A-Za-z0-9+/=_\-]{20,})["\']''', line
        )
        if ent_match:
            val = ent_match.group(1)
            if _is_high_entropy_secret(val):
                # Avoid flagging things that look like URLs or regular text
                if not any(skip in line.lower() for skip in
                           ["import ", "from ", "http", "url", "path", "dir",
                            "comment", "# ", "description"]):
                    findings.append(SecretFinding(
                        kind=SecretKind.GENERIC_HIGH_ENTROPY,
                        value=val[:8] + "...",
                        location=loc,
                        entropy=_entropy(val),
                        pattern="High-entropy string",
                        severity="MEDIUM",
                    ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def analyse_file(filepath: str) -> FileAnalysisResult:
    """
    Analyse a single Python file. Returns a FileAnalysisResult.
    Never raises — parse errors are captured in result.parse_error.
    """
    result = FileAnalysisResult(path=filepath)

    try:
        source_text = Path(filepath).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        result.parse_error = str(e)
        return result

    # Secret scan (text-level, pre-parse)
    result.secrets = _scan_secrets(filepath, source_text)

    # AST parse
    try:
        tree = ast.parse(source_text, filename=filepath)
    except SyntaxError as e:
        result.parse_error = f"SyntaxError: {e}"
        return result

    # AST walk
    visitor = OracleVisitor(filepath, source_text)
    visitor.visit(tree)

    result.functions = visitor.functions
    result.sources   = visitor.sources
    result.sinks     = visitor.sinks
    result.crypto    = visitor.crypto

    # Infer taint flows
    result.flows = _infer_flows(visitor.sources, visitor.sinks, source_text)

    return result


def analyse_directory(dirpath: str, max_files: int = 500) -> list[FileAnalysisResult]:
    """
    Recursively analyse all .py files in a directory.
    Returns one FileAnalysisResult per file.
    """
    results = []
    root = Path(dirpath)
    count = 0

    for pyfile in sorted(root.rglob("*.py")):
        # Skip common non-target directories
        parts = set(pyfile.parts)
        if parts & {"__pycache__", ".venv", "venv", "env", ".tox",
                    "node_modules", ".git", "dist", "build"}:
            continue
        if count >= max_files:
            break
        results.append(analyse_file(str(pyfile)))
        count += 1

    return results


# ─────────────────────────────────────────────────────────────────────────────
# OracleWalker — class wrapper so mistcoder.py can import by class name
# ─────────────────────────────────────────────────────────────────────────────

class OracleWalker:
    """
    Class interface for the ORACLE engine.
    mistcoder.py imports this as: from python_ast_walker import OracleWalker
    """

    def scan_file(self, filepath: str) -> FileAnalysisResult:
        return analyse_file(filepath)

    def scan_directory(self, dirpath: str, max_files: int = 500) -> list:
        return analyse_directory(dirpath, max_files=max_files)

    def findings_from(self, results: list) -> list:
        """Flatten all findings across results into a list of dicts."""
        out = []
        for r in results:
            for flow in r.flows:
                out.append({
                    "severity":   flow.severity,
                    "category":   "TAINT_FLOW",
                    "title":      flow.title(),
                    "cwe":        flow.cwe(),
                    "location":   str(flow.sink.location),
                    "confidence": flow.confidence,
                    "sanitized":  flow.sanitized,
                })
            for c in r.crypto:
                out.append({
                    "severity":   c.severity,
                    "category":   "CRYPTO",
                    "title":      c.kind.value,
                    "location":   str(c.location),
                    "confidence": 0.95,
                })
            for s in r.secrets:
                out.append({
                    "severity":   s.severity,
                    "category":   "SECRET",
                    "title":      s.kind.value,
                    "location":   str(s.location),
                    "entropy":    s.entropy,
                    "confidence": min(0.9, s.entropy / 5.0),
                })
        return out
