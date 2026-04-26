# blockchain/lang/js_scanner.py
# MISTCODER Layer 9 — JavaScript Scanner
#
# Scans .js and .ts files for dangerous patterns.
# No external parser — pure regex + AST-style line analysis.
# Findings map to the same CWE taxonomy as the Python scanner.
# Output feeds directly into the Trinity pipeline.

import re
import json
from pathlib import Path
from datetime import datetime, timezone

# ── Threat patterns ───────────────────────────────────────────────────────────
# Each pattern: (regex, call_name, cwe_id, severity, cvss_score, description)

JS_PATTERNS = [
    # Code injection
    (r'\beval\s*\(',              "eval_exec",        "CWE-94",  "CRITICAL", 9.0,
     "eval() executes arbitrary code — remote code execution vector"),
    (r'\bFunction\s*\(',          "eval_exec",        "CWE-94",  "CRITICAL", 8.5,
     "Function() constructor executes arbitrary code"),
    (r'\bsetTimeout\s*\(\s*[\'"]',"eval_exec",        "CWE-94",  "HIGH",     7.5,
     "setTimeout with string argument executes arbitrary code"),
    (r'\bsetInterval\s*\(\s*[\'"]',"eval_exec",       "CWE-94",  "HIGH",     7.5,
     "setInterval with string argument executes arbitrary code"),

    # Injection
    (r'innerHTML\s*=',            "xss_inject",       "CWE-79",  "HIGH",     7.0,
     "innerHTML assignment may inject unsanitised HTML"),
    (r'document\.write\s*\(',     "xss_inject",       "CWE-79",  "HIGH",     7.0,
     "document.write() with user input causes XSS"),
    (r'outerHTML\s*=',            "xss_inject",       "CWE-79",  "HIGH",     7.0,
     "outerHTML assignment may inject unsanitised HTML"),

    # SQL injection (Node.js)
    (r'query\s*\(\s*[`\'"].*\+',  "sql_query",        "CWE-89",  "CRITICAL", 9.0,
     "SQL query constructed with string concatenation — injection risk"),
    (r'\.query\s*\(`.*\$\{',      "sql_query",        "CWE-89",  "CRITICAL", 9.0,
     "SQL query with template literal interpolation — injection risk"),

    # Path traversal
    (r'path\.join\s*\(.*req\.',   "file_path",        "CWE-22",  "HIGH",     7.5,
     "File path constructed from request data — traversal risk"),
    (r'fs\.read.*req\.',          "file_path",        "CWE-22",  "HIGH",     7.5,
     "File read with user-controlled path"),
    (r'require\s*\(.*req\.',      "file_path",        "CWE-22",  "CRITICAL", 8.5,
     "Dynamic require() with user input — code execution risk"),

    # Hardcoded secrets
    (r'(?i)(password|passwd|secret|api_?key|token)\s*[=:]\s*[\'"][^\'"]{6,}[\'"]',
                                  "hardcoded_secret", "CWE-312", "HIGH",     7.5,
     "Hardcoded credential found in source"),
    (r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}',
                                  "hardcoded_secret", "CWE-312", "HIGH",     7.0,
     "Hardcoded bearer token found"),

    # Weak crypto
    (r'(?i)createHash\s*\(\s*[\'"]md5[\'"]',  "weak_hash", "CWE-327", "MEDIUM", 5.5,
     "MD5 is cryptographically broken"),
    (r'(?i)createHash\s*\(\s*[\'"]sha1[\'"]', "weak_hash", "CWE-327", "MEDIUM", 5.5,
     "SHA1 is deprecated for security use"),
    (r'(?i)createCipher\b',       "weak_hash",        "CWE-327", "HIGH",     7.0,
     "createCipher is deprecated — use createCipheriv"),

    # Deserialization
    (r'JSON\.parse\s*\(.*req\.',  "deserialization",  "CWE-502", "HIGH",     7.5,
     "JSON.parse on request data without validation"),
    (r'\.unserialize\s*\(',       "deserialization",  "CWE-502", "CRITICAL", 9.0,
     "PHP-style unserialize in Node — arbitrary object injection"),
    (r'node-serialize|serialize-javascript', "deserialization", "CWE-502", "CRITICAL", 9.0,
     "Unsafe serialization library detected"),

    # Command injection
    (r'exec\s*\(.*req\.',         "cmd_inject",       "CWE-78",  "CRITICAL", 9.5,
     "Shell command built from request data — OS command injection"),
    (r'spawn\s*\(.*req\.',        "cmd_inject",       "CWE-78",  "CRITICAL", 9.5,
     "Child process spawned with user-controlled arguments"),
    (r'execSync\s*\(',            "cmd_inject",       "CWE-78",  "HIGH",     8.0,
     "Synchronous shell execution — blocks event loop and injection risk"),

    # Information exposure
    (r'console\.(log|error|warn)\s*\(.*(?:password|token|secret|key)',
                                  "info_leak",        "CWE-200", "MEDIUM",   5.0,
     "Sensitive data logged to console"),
    (r'process\.env\.\w+.*console',"info_leak",       "CWE-200", "MEDIUM",   5.0,
     "Environment variable exposed via console"),

    # Prototype pollution
    (r'__proto__\s*\[',           "proto_pollution",  "CWE-1321","HIGH",     8.0,
     "Prototype pollution via __proto__ assignment"),
    (r'constructor\s*\[.*\]\s*=', "proto_pollution",  "CWE-1321","HIGH",     8.0,
     "Prototype pollution via constructor property"),
]


class JSScanner:
    """
    JavaScript/TypeScript security scanner.
    Scans .js, .ts, .mjs files for dangerous patterns.
    Outputs findings in the same format as MISTCODER's Python scanner.
    """

    def __init__(self):
        self.findings = []

    def scan_file(self, filepath: Path) -> list:
        """Scan a single JS/TS file. Returns list of findings."""
        findings = []
        try:
            lines = filepath.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return []

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip comments
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            for pattern, call_name, cwe_id, severity, cvss, description in JS_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "call_name"  : call_name,
                        "cwe_id"     : cwe_id,
                        "severity"   : severity,
                        "cvss_score" : cvss,
                        "file"       : str(filepath),
                        "line"       : lineno,
                        "title"      : description,
                        "language"   : "javascript",
                        "snippet"    : stripped[:120]
                    })
                    break  # one finding per line

        return findings

    def scan_directory(self, target: Path) -> dict:
        """Scan all JS/TS files in a directory tree."""
        target    = Path(target)
        all_files = list(target.rglob("*.js")) + \
                    list(target.rglob("*.ts")) + \
                    list(target.rglob("*.mjs"))

        # Skip node_modules
        all_files = [f for f in all_files
                     if "node_modules" not in f.parts
                     and ".min." not in f.name]

        print(f"[JS SCANNER] Scanning {len(all_files)} JS/TS files in {target}")

        self.findings = []
        for filepath in all_files:
            self.findings.extend(self.scan_file(filepath))

        summary = self._summarise()
        print(f"[JS SCANNER] Found {len(self.findings)} findings across "
              f"{len(all_files)} files")
        print(f"[JS SCANNER] CRITICAL:{summary['critical']} "
              f"HIGH:{summary['high']} MEDIUM:{summary['medium']}")

        return {
            "language"  : "javascript",
            "scanner"   : "MISTCODER JS Scanner v1.0",
            "target"    : str(target),
            "files"     : len(all_files),
            "findings"  : self.findings,
            "summary"   : summary,
            "scanned_at": datetime.now(timezone.utc).isoformat()
        }

    def scan_code(self, code: str, filename: str = "inline.js") -> list:
        """Scan a code string directly — used by the Oracle API."""
        tmp = Path(filename)
        lines = code.splitlines()
        findings = []
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            for pattern, call_name, cwe_id, severity, cvss, description in JS_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "call_name" : call_name,
                        "cwe_id"    : cwe_id,
                        "severity"  : severity,
                        "cvss_score": cvss,
                        "file"      : filename,
                        "line"      : lineno,
                        "title"     : description,
                        "language"  : "javascript",
                        "snippet"   : stripped[:120]
                    })
                    break
        return findings

    def _summarise(self) -> dict:
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        for f in self.findings:
            s = f.get("severity", "LOW").lower()
            sev[s]       = sev.get(s, 0) + 1
            sev["total"] += 1
        return sev