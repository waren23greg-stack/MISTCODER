"""
MISTCODER  MOD-01 EXTENSION  |  URL Scanner
─────────────────────────────────────────────────────────────────────────────
Accepts any URL target:

  • Web application URL     https://target.com
  • API endpoint URL        https://api.target.com/v1/users
  • AI service URL          https://api.openai.com / huggingface.co
  • Admin panel URL         https://target.com/admin
  • Local network URL       http://192.168.1.1

Pipeline:
  URL → Crawler → JSExtractor → SecretScanner → HeaderAnalyzer
      → EndpointMapper → IRBuilder → MOD-01 IR JSON

Everything feeds into the same MOD-02 → MOD-03 pipeline unchanged.
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
import ssl
import html
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

VERSION = "1.0.0"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)

# Security-relevant HTTP headers to audit
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
]

# Dangerous JS patterns to detect in extracted scripts
DANGEROUS_JS_PATTERNS: List[Tuple[str, str, str, float]] = [
    # (regex_pattern, label, cwe_id, confidence)
    (r'\beval\s*\(',                    "JS_EVAL",            "CWE-95",  0.95),
    (r'\bFunction\s*\(',                "JS_FUNCTION_CTOR",   "CWE-95",  0.90),
    (r'document\.write\s*\(',           "JS_DOCUMENT_WRITE",  "CWE-79",  0.95),
    (r'\.innerHTML\s*=',                "JS_INNER_HTML",      "CWE-79",  0.90),
    (r'\.outerHTML\s*=',                "JS_OUTER_HTML",      "CWE-79",  0.85),
    (r'setTimeout\s*\(\s*["\']',        "JS_SETTIMEOUT_STR",  "CWE-95",  0.85),
    (r'setInterval\s*\(\s*["\']',       "JS_SETINTERVAL_STR", "CWE-95",  0.85),
    (r'location\.href\s*=',             "OPEN_REDIRECT",      "CWE-601", 0.75),
    (r'window\.location\s*=',           "OPEN_REDIRECT",      "CWE-601", 0.75),
    (r'postMessage\s*\(',               "JS_POSTMESSAGE",     "CWE-79",  0.70),
    (r'localStorage\s*\[',              "STORAGE_ACCESS",     "CWE-922", 0.65),
    (r'sessionStorage\s*\[',            "STORAGE_ACCESS",     "CWE-922", 0.65),
    (r'crypto\.subtle',                 "WEBCRYPTO_USAGE",    "CWE-327", 0.60),
    (r'XMLHttpRequest|fetch\s*\(',      "HTTP_REQUEST",       "CWE-918", 0.55),
    (r'WebSocket\s*\(',                 "WEBSOCKET",          "CWE-918", 0.60),
    (r'\.src\s*=\s*[^;]+user|input',   "DOM_SRC_INJECTION",  "CWE-79",  0.75),
]

# Secret / credential patterns
SECRET_PATTERNS: List[Tuple[str, str]] = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})',  "API_KEY"),
    (r'(?i)(secret|password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})',      "SECRET"),
    (r'(?i)(token|auth[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})', "TOKEN"),
    (r'(?i)bearer\s+([A-Za-z0-9_\-\.]{16,})',                             "BEARER_TOKEN"),
    (r'AIza[0-9A-Za-z\-_]{35}',                                           "GOOGLE_API_KEY"),
    (r'sk-[A-Za-z0-9]{48}',                                               "OPENAI_KEY"),
    (r'hf_[A-Za-z0-9]{36}',                                               "HUGGINGFACE_KEY"),
    (r'(?i)aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*([A-Z0-9]{20})',       "AWS_KEY"),
    (r'(?i)-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----',                     "PRIVATE_KEY"),
    (r'(?i)(mongodb|postgres|mysql|redis)://[^\s"\'<>]{10,}',             "DB_CONNECTION_STRING"),
    (r'(?i)(github|gitlab)\.com/[^/\s"\']{3,}/[^/\s"\']{3,}\.git',       "GIT_REPO_URL"),
    (r'[0-9a-f]{32,}',                                                    "POTENTIAL_HASH_OR_KEY"),
]

# Endpoints that suggest dangerous functionality
SENSITIVE_ENDPOINT_PATTERNS = [
    (r'/admin',          "ADMIN_PANEL",     "HIGH"),
    (r'/api/',           "API_ENDPOINT",    "MEDIUM"),
    (r'/graphql',        "GRAPHQL",         "HIGH"),
    (r'/login',          "AUTH_ENDPOINT",   "MEDIUM"),
    (r'/auth',           "AUTH_ENDPOINT",   "MEDIUM"),
    (r'/oauth',          "OAUTH_ENDPOINT",  "HIGH"),
    (r'/upload',         "FILE_UPLOAD",     "HIGH"),
    (r'/download',       "FILE_DOWNLOAD",   "MEDIUM"),
    (r'/webhook',        "WEBHOOK",         "HIGH"),
    (r'/debug',          "DEBUG_ENDPOINT",  "CRITICAL"),
    (r'/metrics',        "METRICS",         "MEDIUM"),
    (r'/health',         "HEALTH_CHECK",    "LOW"),
    (r'/swagger',        "API_DOCS",        "HIGH"),
    (r'/openapi',        "API_DOCS",        "HIGH"),
    (r'/actuator',       "SPRING_ACTUATOR", "CRITICAL"),
    (r'/phpinfo',        "PHP_INFO",        "CRITICAL"),
    (r'\.env',           "ENV_FILE",        "CRITICAL"),
    (r'/\.git',          "GIT_EXPOSED",     "CRITICAL"),
    (r'/backup',         "BACKUP_FILE",     "HIGH"),
    (r'/wp-admin',       "WORDPRESS_ADMIN", "HIGH"),
    (r'/config',         "CONFIG_EXPOSED",  "HIGH"),
    (r'/internal',       "INTERNAL_ROUTE",  "HIGH"),
]


# ──────────────────────────────────────────────────────────────────────────────
# HTTP Fetcher (stdlib only, no requests dependency)
# ──────────────────────────────────────────────────────────────────────────────

class HTTPFetcher:
    """
    Fetches URLs using stdlib urllib.
    Handles redirects, TLS, timeouts, and error codes.
    """

    TIMEOUT = 15

    def __init__(self) -> None:
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode    = ssl.CERT_NONE   # scan mode: accept self-signed

    def fetch(self, url: str) -> Dict[str, Any]:
        """
        Fetch a URL and return:
            { status, headers, body, final_url, elapsed_ms, error }
        """
        t0 = time.perf_counter()
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

        try:
            with urllib.request.urlopen(req, timeout=self.TIMEOUT,
                                        context=self._ctx) as resp:
                body = resp.read(1024 * 512)   # max 512 KB
                try:
                    body_str = body.decode("utf-8", errors="replace")
                except Exception:
                    body_str = ""

                headers = dict(resp.headers)
                return {
                    "status":     resp.status,
                    "headers":    {k.lower(): v for k, v in headers.items()},
                    "body":       body_str,
                    "final_url":  resp.url,
                    "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
                    "error":      None,
                }
        except urllib.error.HTTPError as e:
            return {
                "status":     e.code,
                "headers":    {k.lower(): v for k, v in dict(e.headers).items()},
                "body":       "",
                "final_url":  url,
                "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
                "error":      f"HTTP {e.code}: {e.reason}",
            }
        except Exception as e:
            return {
                "status":     0,
                "headers":    {},
                "body":       "",
                "final_url":  url,
                "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
                "error":      str(e),
            }


# ──────────────────────────────────────────────────────────────────────────────
# JS Extractor — pulls inline and linked scripts from HTML
# ──────────────────────────────────────────────────────────────────────────────

class JSExtractor:

    # Matches <script ...>...</script> (inline)
    _INLINE_RE  = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
    # Matches <script src="...">
    _SRC_RE     = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
    # Matches href="/path" or action="/path"
    _LINK_RE    = re.compile(r'(?:href|src|action)=["\']([^"\'#\s]{3,})["\']', re.IGNORECASE)

    def extract_inline(self, html_body: str) -> List[str]:
        return [m.group(1).strip() for m in self._INLINE_RE.finditer(html_body)
                if m.group(1).strip()]

    def extract_script_urls(self, html_body: str, base_url: str) -> List[str]:
        urls = []
        for m in self._SRC_RE.finditer(html_body):
            src = m.group(1)
            urls.append(urllib.parse.urljoin(base_url, src))
        return urls

    def extract_links(self, html_body: str, base_url: str) -> List[str]:
        links = []
        parsed_base = urllib.parse.urlparse(base_url)
        for m in self._LINK_RE.finditer(html_body):
            href = m.group(1)
            full = urllib.parse.urljoin(base_url, href)
            parsed = urllib.parse.urlparse(full)
            # Stay on same domain
            if parsed.netloc == parsed_base.netloc:
                links.append(full)
        return list(set(links))


# ──────────────────────────────────────────────────────────────────────────────
# Header Analyzer — audits HTTP response headers for misconfigurations
# ──────────────────────────────────────────────────────────────────────────────

class HeaderAnalyzer:

    def analyze(self, headers: Dict[str, str], url: str) -> List[Dict[str, Any]]:
        findings = []

        # Missing security headers
        missing = [h for h in [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
        ] if h not in headers]

        for h in missing:
            findings.append({
                "kind":       f"MISSING_HEADER_{h.upper().replace('-','_')}",
                "severity":   "MEDIUM",
                "confidence": 1.0,
                "cwe_ids":    ["CWE-693"],
                "detail":     f"Security header '{h}' is absent",
                "url":        url,
            })

        # Information disclosure headers
        for h in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]:
            if h in headers:
                findings.append({
                    "kind":       "INFO_DISCLOSURE_HEADER",
                    "severity":   "LOW",
                    "confidence": 1.0,
                    "cwe_ids":    ["CWE-200"],
                    "detail":     f"Header '{h}: {headers[h]}' reveals server technology",
                    "url":        url,
                })

        # Dangerous CORS
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            findings.append({
                "kind":       "CORS_WILDCARD_WITH_CREDENTIALS",
                "severity":   "CRITICAL",
                "confidence": 1.0,
                "cwe_ids":    ["CWE-942"],
                "detail":     "CORS allows all origins with credentials — full CSRF/data exfil risk",
                "url":        url,
            })
        elif acao == "*":
            findings.append({
                "kind":       "CORS_WILDCARD",
                "severity":   "MEDIUM",
                "confidence": 0.9,
                "cwe_ids":    ["CWE-942"],
                "detail":     "CORS wildcard origin — cross-origin reads possible",
                "url":        url,
            })

        # HSTS misconfiguration
        hsts = headers.get("strict-transport-security", "")
        if hsts and "max-age=0" in hsts:
            findings.append({
                "kind":       "HSTS_DISABLED",
                "severity":   "HIGH",
                "confidence": 1.0,
                "cwe_ids":    ["CWE-319"],
                "detail":     "HSTS is explicitly disabled (max-age=0)",
                "url":        url,
            })

        return findings


# ──────────────────────────────────────────────────────────────────────────────
# Secret Scanner — finds credentials leaked into HTML/JS
# ──────────────────────────────────────────────────────────────────────────────

class SecretScanner:

    def scan(self, text: str, source_url: str) -> List[Dict[str, Any]]:
        findings = []
        for pattern, label in SECRET_PATTERNS:
            for m in re.finditer(pattern, text):
                val = m.group(0)
                # Skip very short or obviously non-secret matches
                if len(val) < 12:
                    continue
                # Skip common false positives
                if val.lower() in {"password", "secret", "token", "apikey"}:
                    continue
                findings.append({
                    "kind":       f"SECRET_{label}",
                    "severity":   "CRITICAL",
                    "confidence": 0.80,
                    "cwe_ids":    ["CWE-312", "CWE-798"],
                    "detail":     f"Potential {label} exposed in page source: {val[:30]}...",
                    "url":        source_url,
                })
        return findings


# ──────────────────────────────────────────────────────────────────────────────
# JS Analyzer — pattern-matches extracted JavaScript
# ──────────────────────────────────────────────────────────────────────────────

class JSAnalyzer:

    def analyze(self, js_code: str, source_url: str) -> List[Dict[str, Any]]:
        findings = []
        lines = js_code.split("\n")

        for pattern, label, cwe, confidence in DANGEROUS_JS_PATTERNS:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    findings.append({
                        "kind":       label,
                        "severity":   self._severity(label),
                        "confidence": confidence,
                        "cwe_ids":    [cwe],
                        "detail":     f"{label} detected in JS: {line.strip()[:80]}",
                        "url":        source_url,
                        "line":       i,
                    })
        return findings

    @staticmethod
    def _severity(label: str) -> str:
        if label in {"JS_EVAL", "JS_FUNCTION_CTOR", "JS_DOCUMENT_WRITE"}:
            return "CRITICAL"
        if label in {"JS_INNER_HTML", "JS_OUTER_HTML", "OPEN_REDIRECT",
                     "JS_SETTIMEOUT_STR", "JS_SETINTERVAL_STR"}:
            return "HIGH"
        return "MEDIUM"


# ──────────────────────────────────────────────────────────────────────────────
# Endpoint Mapper — discovers and classifies URL paths
# ──────────────────────────────────────────────────────────────────────────────

class EndpointMapper:

    # Common sensitive paths to probe
    PROBE_PATHS = [
        "/.env", "/.git/config", "/config.php", "/wp-config.php",
        "/phpinfo.php", "/admin", "/admin/login", "/api/v1",
        "/api/v2", "/graphql", "/swagger.json", "/openapi.json",
        "/actuator", "/actuator/env", "/debug", "/metrics",
        "/health", "/status", "/robots.txt", "/sitemap.xml",
        "/backup.zip", "/backup.sql", "/dump.sql",
        "/.DS_Store", "/web.config", "/server-status",
    ]

    def __init__(self, fetcher: HTTPFetcher) -> None:
        self._fetcher = fetcher

    def probe(self, base_url: str, max_probes: int = 20) -> List[Dict[str, Any]]:
        """Probe known sensitive paths and classify responses."""
        parsed  = urllib.parse.urlparse(base_url)
        origin  = f"{parsed.scheme}://{parsed.netloc}"
        results = []

        for path in self.PROBE_PATHS[:max_probes]:
            url  = origin + path
            resp = self._fetcher.fetch(url)
            if resp["status"] in {200, 301, 302, 403, 401}:
                sev = self._classify_probe(path, resp["status"])
                results.append({
                    "url":     url,
                    "path":    path,
                    "status":  resp["status"],
                    "kind":    self._label(path),
                    "severity": sev,
                    "accessible": resp["status"] == 200,
                })
                # Small delay to be a polite scanner
                time.sleep(0.1)

        return results

    def map_discovered(self, links: List[str]) -> List[Dict[str, Any]]:
        """Classify discovered links against sensitive patterns."""
        results = []
        for url in links:
            path = urllib.parse.urlparse(url).path
            for pattern, label, severity in SENSITIVE_ENDPOINT_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    results.append({
                        "url":      url,
                        "path":     path,
                        "kind":     label,
                        "severity": severity,
                        "source":   "crawled",
                    })
                    break
        return results

    @staticmethod
    def _classify_probe(path: str, status: int) -> str:
        if any(p in path for p in [".env", ".git", "phpinfo", "actuator", "backup"]):
            return "CRITICAL" if status == 200 else "HIGH"
        if "/admin" in path or "/config" in path:
            return "HIGH"
        return "MEDIUM"

    @staticmethod
    def _label(path: str) -> str:
        for pattern, label, _ in SENSITIVE_ENDPOINT_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                return label
        return "SENSITIVE_PATH"


# ──────────────────────────────────────────────────────────────────────────────
# IR Builder — converts all scan findings into MOD-01 IR JSON format
# ──────────────────────────────────────────────────────────────────────────────

class IRBuilder:
    """
    Produces a MOD-01-compatible IR document from URL scan results.
    All downstream modules (MOD-02, MOD-03) consume this unchanged.
    """

    def build(
        self,
        target_url:       str,
        header_findings:  List[Dict],
        js_findings:      List[Dict],
        secret_findings:  List[Dict],
        endpoint_results: List[Dict],
        probe_results:    List[Dict],
        response_meta:    Dict[str, Any],
    ) -> Dict[str, Any]:

        all_findings = (
            header_findings + js_findings + secret_findings
        )

        nodes = []
        edges = []
        node_id = 0

        # Root node — the target URL itself
        root_id = f"url_root_{node_id}"
        nodes.append({
            "id":   root_id,
            "type": "url_target",
            "name": target_url,
            "line": 0,
            "props": {
                "status":       response_meta.get("status"),
                "server":       response_meta.get("server", "unknown"),
                "elapsed_ms":   response_meta.get("elapsed_ms"),
                "final_url":    response_meta.get("final_url", target_url),
            }
        })
        node_id += 1

        # Finding nodes
        for f in all_findings:
            nid = f"finding_{node_id}"
            node_id += 1
            is_dangerous = f["severity"] in {"CRITICAL", "HIGH"}
            nodes.append({
                "id":   nid,
                "type": "url_finding",
                "name": f["kind"],
                "line": f.get("line", 0),
                "props": {
                    "dangerous":  is_dangerous,
                    "severity":   f["severity"],
                    "confidence": f["confidence"],
                    "cwe_ids":    f["cwe_ids"],
                    "detail":     f["detail"],
                    "url":        f.get("url", target_url),
                },
            })
            edges.append({
                "src":  root_id,
                "dst":  nid,
                "type": "has_finding",
            })

        # Endpoint nodes
        for ep in endpoint_results + probe_results:
            if not ep.get("kind"):
                continue
            nid = f"endpoint_{node_id}"
            node_id += 1
            is_dangerous = ep.get("severity") in {"CRITICAL", "HIGH"}
            accessible   = ep.get("accessible", ep.get("status") == 200)
            nodes.append({
                "id":   nid,
                "type": "endpoint",
                "name": ep.get("kind", "ENDPOINT"),
                "line": 0,
                "props": {
                    "dangerous":  is_dangerous and accessible,
                    "severity":   ep.get("severity", "MEDIUM"),
                    "url":        ep.get("url", ""),
                    "path":       ep.get("path", ""),
                    "status":     ep.get("status", 0),
                    "accessible": accessible,
                    "confidence": 0.95 if accessible else 0.50,
                    "cwe_ids":    ["CWE-538"],
                },
            })
            edges.append({
                "src":  root_id,
                "dst":  nid,
                "type": "exposes_endpoint",
            })

        dangerous_count = sum(
            1 for n in nodes
            if n.get("props", {}).get("dangerous")
        )
        secret_count = sum(
            1 for f in secret_findings
        )

        body_hash = hashlib.sha256(
            response_meta.get("body_snippet", "").encode()
        ).hexdigest()

        return {
            "file":     target_url,
            "language": "url",
            "scan_type": "remote_url",
            "nodes":    nodes,
            "edges":    edges,
            "metadata": {
                "version":         VERSION,
                "target_url":      target_url,
                "final_url":       response_meta.get("final_url", target_url),
                "status_code":     response_meta.get("status"),
                "server":          response_meta.get("server", "unknown"),
                "elapsed_ms":      response_meta.get("elapsed_ms"),
                "dangerous_calls": dangerous_count,
                "secret_flags":    secret_count,
                "endpoints_found": len(endpoint_results) + len(probe_results),
                "sha256":          body_hash,
                "parsed_at":       datetime.now(timezone.utc).isoformat(),
            },
        }


# ──────────────────────────────────────────────────────────────────────────────
# URL Scanner — top-level orchestrator
# ──────────────────────────────────────────────────────────────────────────────

class URLScanner:
    """
    Main entry point for URL-based scanning.

    Usage:
        scanner = URLScanner()
        ir      = scanner.scan("https://target.com")
        scanner.export(ir, "sandbox/target_ir.json")
    """

    def __init__(
        self,
        max_js_scripts:  int  = 5,
        probe_endpoints: bool = True,
        crawl_links:     bool = True,
        verbose:         bool = True,
    ) -> None:
        self._fetcher  = HTTPFetcher()
        self._js_ext   = JSExtractor()
        self._js_anal  = JSAnalyzer()
        self._headers  = HeaderAnalyzer()
        self._secrets  = SecretScanner()
        self._endpoints = EndpointMapper(self._fetcher)
        self._ir       = IRBuilder()
        self._max_js   = max_js_scripts
        self._probe    = probe_endpoints
        self._crawl    = crawl_links
        self._verbose  = verbose

    def scan(self, url: str) -> Dict[str, Any]:
        """
        Full scan of a URL target.
        Returns MOD-01-compatible IR JSON dict.
        """
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        self._log(f"\n{'═'*64}")
        self._log(f"  MISTCODER  ·  URL Scanner v{VERSION}")
        self._log(f"  Target : {url}")
        self._log(f"{'═'*64}")

        # ── Step 1: Fetch main page ───────────────────────────────────────────
        self._log("\n  [1/5] Fetching target...")
        resp = self._fetcher.fetch(url)

        if resp["error"] and resp["status"] == 0:
            self._log(f"  ✗ Unreachable: {resp['error']}")
            return self._error_ir(url, resp["error"])

        self._log(f"  ✓ Status {resp['status']}  ({resp['elapsed_ms']} ms)  "
                  f"→ {resp['final_url']}")

        body    = resp["body"]
        headers = resp["headers"]
        server  = headers.get("server", headers.get("x-powered-by", "unknown"))

        # ── Step 2: Analyze headers ───────────────────────────────────────────
        self._log("\n  [2/5] Analyzing HTTP headers...")
        header_findings = self._headers.analyze(headers, url)
        self._log(f"  ✓ {len(header_findings)} header findings")

        # ── Step 3: Extract and analyze JavaScript ────────────────────────────
        self._log("\n  [3/5] Extracting JavaScript...")
        all_js_findings: List[Dict] = []
        all_secret_findings: List[Dict] = []

        # Inline scripts
        inline_scripts = self._js_ext.extract_inline(body)
        self._log(f"  ✓ {len(inline_scripts)} inline scripts found")

        for script in inline_scripts:
            all_js_findings  += self._js_anal.analyze(script, url)
            all_secret_findings += self._secrets.scan(script, url)

        # Scan body for secrets too
        all_secret_findings += self._secrets.scan(body, url)

        # External scripts (up to max_js)
        script_urls = self._js_ext.extract_script_urls(body, url)
        self._log(f"  ✓ {len(script_urls)} external scripts found")

        for js_url in script_urls[:self._max_js]:
            self._log(f"    → fetching {js_url[:60]}...")
            js_resp = self._fetcher.fetch(js_url)
            if not js_resp["error"] and js_resp["body"]:
                all_js_findings     += self._js_anal.analyze(js_resp["body"], js_url)
                all_secret_findings += self._secrets.scan(js_resp["body"], js_url)

        self._log(f"  ✓ {len(all_js_findings)} JS findings, "
                  f"{len(all_secret_findings)} secret findings")

        # ── Step 4: Crawl links + map endpoints ──────────────────────────────
        endpoint_results: List[Dict] = []
        probe_results:    List[Dict] = []

        if self._crawl:
            self._log("\n  [4/5] Mapping endpoints...")
            links = self._js_ext.extract_links(body, url)
            self._log(f"  ✓ {len(links)} internal links discovered")
            endpoint_results = self._endpoints.map_discovered(links)
            self._log(f"  ✓ {len(endpoint_results)} sensitive endpoints mapped")
        else:
            self._log("\n  [4/5] Skipping crawl (disabled)")

        if self._probe:
            self._log("\n  [4b] Probing known sensitive paths...")
            probe_results = self._endpoints.probe(url, max_probes=15)
            accessible    = [p for p in probe_results if p.get("accessible")]
            self._log(f"  ✓ {len(probe_results)} paths probed, "
                      f"{len(accessible)} accessible")

        # ── Step 5: Build IR ──────────────────────────────────────────────────
        self._log("\n  [5/5] Building IR...")
        response_meta = {
            "status":       resp["status"],
            "server":       server,
            "elapsed_ms":   resp["elapsed_ms"],
            "final_url":    resp["final_url"],
            "body_snippet": body[:500],
        }

        ir = self._ir.build(
            target_url       = url,
            header_findings  = header_findings,
            js_findings      = all_js_findings,
            secret_findings  = all_secret_findings,
            endpoint_results = endpoint_results,
            probe_results    = probe_results,
            response_meta    = response_meta,
        )

        # Print summary
        meta = ir["metadata"]
        self._log(f"\n{'─'*64}")
        self._log(f"  SCAN COMPLETE")
        self._log(f"{'─'*64}")
        self._log(f"  Target         : {url}")
        self._log(f"  Status         : {meta['status_code']}")
        self._log(f"  Server         : {meta['server']}")
        self._log(f"  Nodes          : {len(ir['nodes'])}")
        self._log(f"  Dangerous      : {meta['dangerous_calls']}")
        self._log(f"  Secrets        : {meta['secret_flags']}")
        self._log(f"  Endpoints      : {meta['endpoints_found']}")
        self._log(f"{'─'*64}\n")

        return ir

    def export(self, ir: Dict[str, Any], output_path: str) -> None:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(ir, f, indent=2)
        self._log(f"[URL-SCAN] IR exported to {output_path}")

    def _log(self, msg: str) -> None:
        if self._verbose:
            print(msg)

    def _error_ir(self, url: str, error: str) -> Dict[str, Any]:
        return {
            "file": url, "language": "url", "scan_type": "remote_url",
            "nodes": [], "edges": [],
            "metadata": {
                "version": VERSION, "target_url": url,
                "error": error, "dangerous_calls": 0,
                "secret_flags": 0, "endpoints_found": 0,
                "parsed_at": datetime.now(timezone.utc).isoformat(),
            },
        }


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python url_scanner.py <url> [--export output.json] [--no-probe] [--no-crawl]")
        print("Examples:")
        print("  python url_scanner.py https://example.com")
        print("  python url_scanner.py https://api.target.com/v1 --export sandbox/target_ir.json")
        print("  python url_scanner.py http://192.168.1.1 --no-probe")
        sys.exit(1)

    target      = sys.argv[1]
    export_path = None
    probe       = True
    crawl       = True

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--export" and i + 1 < len(sys.argv):
            export_path = sys.argv[i + 1]; i += 2
        elif sys.argv[i] == "--no-probe":
            probe = False; i += 1
        elif sys.argv[i] == "--no-crawl":
            crawl = False; i += 1
        else:
            i += 1

    scanner = URLScanner(probe_endpoints=probe, crawl_links=crawl)
    ir      = scanner.scan(target)

    if export_path:
        scanner.export(ir, export_path)
    else:
        # Auto-export to sandbox/
        safe_name = re.sub(r'[^\w]', '_', target)[:40]
        auto_path = f"sandbox/url_ir_{safe_name}.json"
        scanner.export(ir, auto_path)
        print(f"[URL-SCAN] Auto-exported to {auto_path}")
