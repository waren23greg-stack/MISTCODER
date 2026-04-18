"""
MISTCODER -- CVE Feed Ingester v0.1.0

Fetches and parses CVE data from the NVD (National Vulnerability Database)
REST API v2.0. Normalizes records into MISTCODER's internal CVERecord schema.

Operates in two modes:
  LIVE   -- pulls from api.nvd.nist.gov (requires network)
  CACHED -- reads from local JSON cache (offline / CI safe)

Output schema per record:
  {
    "cve_id":        str,
    "description":   str,
    "cvss_score":    float,
    "cvss_vector":   str,
    "severity":      str,
    "cwe_ids":       [ str ],
    "affected":      [ str ],
    "published":     str,
    "patterns":      [ str ],   -- extracted attack patterns
    "categories":    [ str ],   -- MISTCODER vulnerability categories
  }
"""

import json
import os
import re
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import Optional


NVD_API_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_DELAY  = 0.6   # NVD rate limit: max 5 req/30s without API key
CACHE_DIR      = os.path.join(os.path.dirname(__file__),
                              "..", "..", "..", "sandbox", "cve_cache")

# Map CWE IDs and keyword patterns to MISTCODER vulnerability categories
CWE_CATEGORY_MAP = {
    "CWE-78":  "COMMAND_INJECTION",
    "CWE-77":  "COMMAND_INJECTION",
    "CWE-89":  "SQL_INJECTION",
    "CWE-79":  "XSS",
    "CWE-22":  "PATH_TRAVERSAL",
    "CWE-502": "INSECURE_DESERIAL",
    "CWE-94":  "DANGEROUS_CALL",
    "CWE-95":  "DANGEROUS_CALL",
    "CWE-798": "HARDCODED_SECRET",
    "CWE-259": "HARDCODED_SECRET",
    "CWE-321": "HARDCODED_SECRET",
    "CWE-200": "SECRET_EXPOSURE",
    "CWE-532": "SECRET_EXPOSURE",
    "CWE-918": "SSRF",
    "CWE-601": "OPEN_REDIRECT",
    "CWE-287": "MISSING_AUTHZ",
    "CWE-306": "MISSING_AUTHZ",
    "CWE-269": "PRIVILEGE_ESC",
    "CWE-434": "DANGEROUS_CALL",
    "CWE-611": "DANGEROUS_CALL",
    "CWE-676": "DANGEROUS_CALL",
}

KEYWORD_CATEGORY_MAP = {
    "command injection":          "COMMAND_INJECTION",
    "os command":                 "COMMAND_INJECTION",
    "shell injection":            "COMMAND_INJECTION",
    "sql injection":              "SQL_INJECTION",
    "sqli":                       "SQL_INJECTION",
    "cross-site scripting":       "XSS",
    "xss":                        "XSS",
    "path traversal":             "PATH_TRAVERSAL",
    "directory traversal":        "PATH_TRAVERSAL",
    "deserialization":            "INSECURE_DESERIAL",
    "pickle":                     "INSECURE_DESERIAL",
    "hardcoded":                  "HARDCODED_SECRET",
    "hard-coded":                 "HARDCODED_SECRET",
    "credentials":                "HARDCODED_SECRET",
    "server-side request forgery":"SSRF",
    "ssrf":                       "SSRF",
    "open redirect":              "OPEN_REDIRECT",
    "remote code execution":      "DANGEROUS_CALL",
    "rce":                        "DANGEROUS_CALL",
    "arbitrary code":             "DANGEROUS_CALL",
    "eval":                       "DANGEROUS_CALL",
    "privilege escalation":       "PRIVILEGE_ESC",
    "unauthorized access":        "MISSING_AUTHZ",
    "authentication bypass":      "MISSING_AUTHZ",
}

ATTACK_PATTERN_KEYWORDS = [
    "eval", "exec", "system(", "popen", "subprocess",
    "pickle", "deserializ", "yaml.load", "marshal",
    "innerHTML", "document.write", "execSync",
    "format(", "f-string", "string concatenat",
    "open(", "file read", "path traversal", "../",
    "SELECT", "INSERT", "UPDATE", "DELETE", "UNION",
    "hardcoded", "plaintext", "base64", "token", "secret",
    "request.args", "request.form", "req.body",
    "os.environ", "getenv", "process.env",
]


def _extract_patterns(description: str) -> list:
    desc_lower = description.lower()
    found = []
    for kw in ATTACK_PATTERN_KEYWORDS:
        if kw.lower() in desc_lower:
            found.append(kw)
    return list(set(found))


def _extract_categories(description: str, cwe_ids: list) -> list:
    categories = set()
    desc_lower = description.lower()
    for cwe in cwe_ids:
        if cwe in CWE_CATEGORY_MAP:
            categories.add(CWE_CATEGORY_MAP[cwe])
    for keyword, category in KEYWORD_CATEGORY_MAP.items():
        if keyword in desc_lower:
            categories.add(category)
    return sorted(categories)


def _parse_nvd_item(item: dict) -> Optional[dict]:
    try:
        cve     = item.get("cve", {})
        cve_id  = cve.get("id", "")
        descs   = cve.get("descriptions", [])
        desc    = next((d["value"] for d in descs
                        if d.get("lang") == "en"), "")
        published = cve.get("published", "")

        # CWE extraction
        weaknesses = cve.get("weaknesses", [])
        cwe_ids = []
        for w in weaknesses:
            for d in w.get("description", []):
                val = d.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)

        # CVSS extraction (prefer v3.1, fallback v3.0, fallback v2)
        metrics  = cve.get("metrics", {})
        cvss_score  = 0.0
        cvss_vector = ""
        severity    = "UNKNOWN"

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                data        = entries[0].get("cvssData", {})
                cvss_score  = data.get("baseScore", 0.0)
                cvss_vector = data.get("vectorString", "")
                severity    = data.get("baseSeverity",
                              entries[0].get("baseSeverity", "UNKNOWN"))
                break

        # Affected products
        configs  = cve.get("configurations", [])
        affected = []
        for config in configs:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    parts = cpe.split(":")
                    if len(parts) > 4:
                        vendor  = parts[3]
                        product = parts[4]
                        if vendor and product and vendor != "*":
                            affected.append(f"{vendor}/{product}")
        affected = list(set(affected))[:10]

        patterns   = _extract_patterns(desc)
        categories = _extract_categories(desc, cwe_ids)

        return {
            "cve_id":      cve_id,
            "description": desc,
            "cvss_score":  cvss_score,
            "cvss_vector": cvss_vector,
            "severity":    severity,
            "cwe_ids":     cwe_ids,
            "affected":    affected,
            "published":   published,
            "patterns":    patterns,
            "categories":  categories,
        }
    except Exception:
        return None


class CVEIngester:
    """
    Fetches CVE records from NVD API and normalizes them.
    Falls back to cache if network is unavailable.
    """

    def __init__(self, cache_dir: str = CACHE_DIR,
                 api_key: str = ""):
        self.cache_dir = cache_dir
        self.api_key   = api_key
        os.makedirs(cache_dir, exist_ok=True)

    def _cache_path(self, key: str) -> str:
        safe = re.sub(r'[^\w]', '_', key)
        return os.path.join(self.cache_dir, f"{safe}.json")

    def _save_cache(self, key: str, data: list) -> None:
        with open(self._cache_path(key), "w", encoding="utf-8") as f:
            json.dump({"fetched_at": datetime.now(timezone.utc).isoformat(),
                       "records": data}, f, indent=2)

    def _load_cache(self, key: str) -> Optional[list]:
        path = self._cache_path(key)
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("records", [])

    def _fetch_nvd(self, params: dict) -> list:
        query  = urllib.parse.urlencode(params)
        url    = f"{NVD_API_BASE}?{query}"
        req    = urllib.request.Request(url)
        req.add_header("User-Agent", "MISTCODER/0.1 Security Research Tool")
        if self.api_key:
            req.add_header("apiKey", self.api_key)

        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = json.loads(resp.read().decode())

        records = []
        for item in raw.get("vulnerabilities", []):
            parsed = _parse_nvd_item(item)
            if parsed:
                records.append(parsed)
        return records

    def fetch_recent(self, days: int = 7,
                     use_cache: bool = True) -> list:
        """
        Fetch CVEs published in the last N days.
        """
        cache_key = f"recent_{days}d"
        if use_cache:
            cached = self._load_cache(cache_key)
            if cached is not None:
                print(f"[INGEST] Loaded {len(cached)} CVEs from cache "
                      f"(key={cache_key})")
                return cached

        end   = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate":   end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 100,
        }

        try:
            records = self._fetch_nvd(params)
            self._save_cache(cache_key, records)
            print(f"[INGEST] Fetched {len(records)} CVEs from NVD "
                  f"(last {days} days)")
            return records
        except Exception as e:
            print(f"[INGEST] NVD fetch failed: {e} -- returning empty list")
            return []

    def fetch_by_category(self, category: str,
                          use_cache: bool = True) -> list:
        """
        Fetch CVEs matching a MISTCODER vulnerability category.
        """
        cache_key = f"category_{category}"
        if use_cache:
            cached = self._load_cache(cache_key)
            if cached is not None:
                print(f"[INGEST] Loaded {len(cached)} CVEs from cache "
                      f"(category={category})")
                return cached

        # Reverse-map category to CWE IDs
        cwe_ids = [cwe for cwe, cat in CWE_CATEGORY_MAP.items()
                   if cat == category]
        if not cwe_ids:
            return []

        all_records = []
        for cwe in cwe_ids[:3]:
            try:
                records = self._fetch_nvd({"cweId": cwe,
                                           "resultsPerPage": 50})
                all_records.extend(records)
                time.sleep(REQUEST_DELAY)
            except Exception as e:
                print(f"[INGEST] Failed {cwe}: {e}")

        deduped = {r["cve_id"]: r for r in all_records}
        result  = list(deduped.values())
        self._save_cache(cache_key, result)
        print(f"[INGEST] Fetched {len(result)} CVEs for category {category}")
        return result

    def load_synthetic(self) -> list:
        """
        Returns a curated synthetic CVE dataset for offline use.
        Mirrors real NVD schema. Used in CI and demo environments.
        """
        return [
            {
                "cve_id": "CVE-2024-SYN-001",
                "description": "Remote code execution via eval() on unsanitized user input in Python web framework. Attacker can execute arbitrary code by submitting crafted expressions to the calculation endpoint.",
                "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "CRITICAL", "cwe_ids": ["CWE-95"],
                "affected": ["python/flask", "python/django"],
                "published": "2024-01-15T00:00:00.000",
                "patterns": ["eval", "exec", "arbitrary code"],
                "categories": ["DANGEROUS_CALL"]
            },
            {
                "cve_id": "CVE-2024-SYN-002",
                "description": "SQL injection vulnerability allows unauthenticated attacker to read sensitive data via string-formatted database queries. No parameterization used.",
                "cvss_score": 9.1, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
                "severity": "CRITICAL", "cwe_ids": ["CWE-89"],
                "affected": ["mysql/connector", "sqlite3"],
                "published": "2024-02-03T00:00:00.000",
                "patterns": ["SELECT", "INSERT", "string concatenat", "format("],
                "categories": ["SQL_INJECTION"]
            },
            {
                "cve_id": "CVE-2024-SYN-003",
                "description": "Hardcoded API key and database password discovered in application source. Credentials provide full administrative access to production database.",
                "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "CRITICAL", "cwe_ids": ["CWE-798", "CWE-259"],
                "affected": ["generic/application"],
                "published": "2024-02-14T00:00:00.000",
                "patterns": ["hardcoded", "plaintext", "token", "secret"],
                "categories": ["HARDCODED_SECRET", "SECRET_EXPOSURE"]
            },
            {
                "cve_id": "CVE-2024-SYN-004",
                "description": "Insecure deserialization via pickle.loads() allows remote code execution. Attacker-controlled serialized objects trigger arbitrary code execution on load.",
                "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "CRITICAL", "cwe_ids": ["CWE-502"],
                "affected": ["python/pickle", "python/shelve"],
                "published": "2024-03-01T00:00:00.000",
                "patterns": ["pickle", "deserializ", "marshal"],
                "categories": ["INSECURE_DESERIAL"]
            },
            {
                "cve_id": "CVE-2024-SYN-005",
                "description": "OS command injection via unsanitized input passed to os.system(). Attacker can execute arbitrary system commands with application privileges.",
                "cvss_score": 10.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "severity": "CRITICAL", "cwe_ids": ["CWE-78"],
                "affected": ["python/os", "python/subprocess"],
                "published": "2024-03-10T00:00:00.000",
                "patterns": ["system(", "popen", "subprocess", "os.environ"],
                "categories": ["COMMAND_INJECTION"]
            },
            {
                "cve_id": "CVE-2024-SYN-006",
                "description": "Path traversal vulnerability in file read endpoint. User-supplied filename parameter allows reading of arbitrary files including /etc/passwd.",
                "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "severity": "HIGH", "cwe_ids": ["CWE-22"],
                "affected": ["generic/file-server"],
                "published": "2024-03-22T00:00:00.000",
                "patterns": ["open(", "file read", "path traversal", "../"],
                "categories": ["PATH_TRAVERSAL"]
            },
            {
                "cve_id": "CVE-2024-SYN-007",
                "description": "Reflected XSS via unescaped user input in render_template_string. Attacker-controlled name parameter is injected directly into HTML response.",
                "cvss_score": 6.1, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "severity": "MEDIUM", "cwe_ids": ["CWE-79"],
                "affected": ["python/flask", "python/jinja2"],
                "published": "2024-04-01T00:00:00.000",
                "patterns": ["innerHTML", "document.write"],
                "categories": ["XSS"]
            },
            {
                "cve_id": "CVE-2024-SYN-008",
                "description": "SSRF vulnerability allows internal network scanning. Server-side request forgery via user-controlled URL parameter with no allowlist validation.",
                "cvss_score": 8.6, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                "severity": "HIGH", "cwe_ids": ["CWE-918"],
                "affected": ["generic/http-client"],
                "published": "2024-04-08T00:00:00.000",
                "patterns": ["request.args", "request.form"],
                "categories": ["SSRF"]
            },
            {
                "cve_id": "CVE-2024-SYN-009",
                "description": "Authentication bypass allows unauthenticated access to admin endpoints. Missing authorization check on privileged route due to decorator misconfiguration.",
                "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "CRITICAL", "cwe_ids": ["CWE-287", "CWE-306"],
                "affected": ["generic/auth-framework"],
                "published": "2024-04-15T00:00:00.000",
                "patterns": ["token", "secret"],
                "categories": ["MISSING_AUTHZ"]
            },
            {
                "cve_id": "CVE-2024-SYN-010",
                "description": "Sensitive data exposure in debug endpoint returns all environment variables, database credentials, and API keys in plaintext JSON response.",
                "cvss_score": 9.1, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
                "severity": "CRITICAL", "cwe_ids": ["CWE-200", "CWE-532"],
                "affected": ["generic/web-application"],
                "published": "2024-04-20T00:00:00.000",
                "patterns": ["os.environ", "getenv", "plaintext", "token"],
                "categories": ["SECRET_EXPOSURE"]
            },
        ]
