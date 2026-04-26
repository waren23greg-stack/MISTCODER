# blockchain/lang/go_scanner.py
# MISTCODER Layer 9 — Go Scanner
#
# Scans .go files for dangerous patterns.
# Maps to the same CWE taxonomy — same Trinity pipeline.

import re
from pathlib import Path
from datetime import datetime, timezone

GO_PATTERNS = [
    # Command injection
    (r'exec\.Command\s*\(.*\+',      "cmd_inject",       "CWE-78",  "CRITICAL", 9.5,
     "exec.Command built with string concatenation — OS injection risk"),
    (r'exec\.CommandContext\s*\(.*\+',"cmd_inject",       "CWE-78",  "CRITICAL", 9.5,
     "exec.CommandContext with concatenated args — OS injection risk"),
    (r'syscall\.Exec\s*\(',          "cmd_inject",       "CWE-78",  "CRITICAL", 9.5,
     "Direct syscall.Exec — OS command execution"),

    # SQL injection
    (r'\.Query\s*\(.*\+',            "sql_query",        "CWE-89",  "CRITICAL", 9.0,
     "SQL query built with string concatenation — injection risk"),
    (r'\.Exec\s*\(.*\+',             "sql_query",        "CWE-89",  "CRITICAL", 9.0,
     "SQL Exec with concatenated string — injection risk"),
    (r'fmt\.Sprintf.*SELECT|INSERT|UPDATE|DELETE',
                                     "sql_query",        "CWE-89",  "CRITICAL", 9.0,
     "SQL query built via fmt.Sprintf — injection risk"),

    # Path traversal
    (r'os\.Open\s*\(.*\+',           "file_path",        "CWE-22",  "HIGH",     7.5,
     "File open with user-controlled path — traversal risk"),
    (r'ioutil\.ReadFile\s*\(.*\+',   "file_path",        "CWE-22",  "HIGH",     7.5,
     "ReadFile with concatenated path — traversal risk"),
    (r'filepath\.Join\s*\(.*r\.',    "file_path",        "CWE-22",  "HIGH",     7.5,
     "filepath.Join with request data — traversal risk"),
    (r'os\.Create\s*\(.*\+',         "file_path",        "CWE-22",  "HIGH",     7.5,
     "os.Create with user-controlled path"),

    # Hardcoded secrets
    (r'(?i)(password|passwd|secret|apikey|api_key|token)\s*:?=\s*"[^"]{6,}"',
                                     "hardcoded_secret", "CWE-312", "HIGH",     7.5,
     "Hardcoded credential in Go source"),
    (r'(?i)const\s+\w*(key|secret|token|pass)\w*\s*=\s*"',
                                     "hardcoded_secret", "CWE-312", "HIGH",     7.5,
     "Hardcoded secret constant"),

    # Weak crypto
    (r'md5\.New\(\)',                 "weak_hash",        "CWE-327", "MEDIUM",   5.5,
     "MD5 is cryptographically broken — use SHA-256"),
    (r'sha1\.New\(\)',                "weak_hash",        "CWE-327", "MEDIUM",   5.5,
     "SHA1 is deprecated for security use"),
    (r'des\.NewCipher\(',            "weak_hash",        "CWE-327", "HIGH",     7.0,
     "DES cipher is broken — use AES"),
    (r'rc4\.NewCipher\(',            "weak_hash",        "CWE-327", "HIGH",     7.0,
     "RC4 stream cipher is broken"),

    # Deserialization
    (r'encoding/gob',                "deserialization",  "CWE-502", "MEDIUM",   6.0,
     "gob deserialization of untrusted data — type confusion risk"),
    (r'yaml\.Unmarshal',             "deserialization",  "CWE-502", "HIGH",     7.5,
     "YAML unmarshal may execute Go code via !!python/object tags"),
    (r'pickle\.',                    "deserialization",  "CWE-502", "CRITICAL", 9.0,
     "pickle deserialization — arbitrary code execution"),

    # Integer overflow
    (r'int32\s*\(\s*.*len\(',        "int_overflow",     "CWE-190", "MEDIUM",   5.5,
     "Integer conversion may overflow on large input"),

    # Race conditions
    (r'go\s+func\s*\(.*\)\s*\{',    "race_condition",   "CWE-362", "MEDIUM",   5.0,
     "Goroutine closure may capture loop variable — race condition"),

    # Information exposure
    (r'log\.\w+\(.*(?:password|token|secret|key)',
                                     "info_leak",        "CWE-200", "MEDIUM",   5.0,
     "Sensitive data written to log"),
    (r'fmt\.(Print|Println|Printf).*(?:password|token|secret)',
                                     "info_leak",        "CWE-200", "MEDIUM",   5.0,
     "Sensitive data printed to stdout"),

    # TLS misconfiguration
    (r'InsecureSkipVerify\s*:\s*true',"tls_misconfig",   "CWE-295", "HIGH",     7.5,
     "TLS certificate verification disabled — MITM risk"),
    (r'tls\.Config\{.*MinVersion',   "tls_misconfig",   "CWE-326", "MEDIUM",   5.5,
     "TLS minimum version may allow weak protocols"),
]


class GoScanner:
    """
    Go security scanner.
    Scans .go files for dangerous patterns.
    Outputs findings compatible with the Trinity pipeline.
    """

    def __init__(self):
        self.findings = []

    def scan_file(self, filepath: Path) -> list:
        findings = []
        try:
            lines = filepath.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return []

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue
            for pattern, call_name, cwe_id, severity, cvss, description in GO_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "call_name" : call_name,
                        "cwe_id"    : cwe_id,
                        "severity"  : severity,
                        "cvss_score": cvss,
                        "file"      : str(filepath),
                        "line"      : lineno,
                        "title"     : description,
                        "language"  : "go",
                        "snippet"   : stripped[:120]
                    })
                    break
        return findings

    def scan_directory(self, target: Path) -> dict:
        target    = Path(target)
        all_files = list(target.rglob("*.go"))
        all_files = [f for f in all_files if "vendor" not in f.parts]

        print(f"[GO SCANNER] Scanning {len(all_files)} Go files in {target}")

        self.findings = []
        for filepath in all_files:
            self.findings.extend(self.scan_file(filepath))

        summary = self._summarise()
        print(f"[GO SCANNER] Found {len(self.findings)} findings")
        print(f"[GO SCANNER] CRITICAL:{summary['critical']} "
              f"HIGH:{summary['high']} MEDIUM:{summary['medium']}")

        return {
            "language"  : "go",
            "scanner"   : "MISTCODER Go Scanner v1.0",
            "target"    : str(target),
            "files"     : len(all_files),
            "findings"  : self.findings,
            "summary"   : summary,
            "scanned_at": datetime.now(timezone.utc).isoformat()
        }

    def scan_code(self, code: str, filename: str = "inline.go") -> list:
        lines    = code.splitlines()
        findings = []
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            for pattern, call_name, cwe_id, severity, cvss, description in GO_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "call_name" : call_name,
                        "cwe_id"    : cwe_id,
                        "severity"  : severity,
                        "cvss_score": cvss,
                        "file"      : filename,
                        "line"      : lineno,
                        "title"     : description,
                        "language"  : "go",
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