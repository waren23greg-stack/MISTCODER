"""
MISTCODER -- Knowledge Base v0.1.0

Persistent, versioned store of learned vulnerability intelligence.
Grows with every ingestion and learning cycle.

The knowledge base contains:
  -- CVE records indexed by ID and category
  -- Learned detection patterns with confidence scores
  -- Category weights updated by scan feedback
  -- Version history of all model updates
  -- Scan result feedback for continuous improvement

The KB is the memory of MISTCODER.
It is what separates a system that was trained once
from a system that never stops learning.
"""

import json
import os
import hashlib
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional


KB_VERSION = "0.1.0"

DEFAULT_CATEGORY_WEIGHTS = {
    "DANGEROUS_CALL":    1.20,
    "COMMAND_INJECTION": 1.25,
    "SQL_INJECTION":     1.15,
    "SECRET_EXPOSURE":   1.35,
    "HARDCODED_SECRET":  1.35,
    "INSECURE_DESERIAL": 1.20,
    "PATH_TRAVERSAL":    1.10,
    "XSS":               1.10,
    "SSRF":              1.15,
    "MISSING_AUTHZ":     1.25,
    "PRIVILEGE_ESC":     1.25,
    "TAINT_FLOW":        1.10,
    "DEFAULT":           1.00,
}


class KnowledgeBase:
    """
    Versioned, persistent knowledge store.
    Supports read, write, update, and export operations.
    """

    def __init__(self, kb_path: Optional[str] = None):
        self.kb_path = kb_path or os.path.join(
            os.path.dirname(__file__),
            "..", "..", "..", "sandbox", "knowledge_base.json"
        )
        self._data = self._load()

    # -----------------------------------------------------------------------
    # Persistence
    # -----------------------------------------------------------------------

    def _empty(self) -> dict:
        return {
            "version":           KB_VERSION,
            "created_at":        datetime.now(timezone.utc).isoformat(),
            "last_updated":      datetime.now(timezone.utc).isoformat(),
            "update_count":      0,
            "cve_count":         0,
            "cves":              {},
            "patterns":          {},
            "category_weights":  dict(DEFAULT_CATEGORY_WEIGHTS),
            "dangerous_calls":   list(_DEFAULT_DANGEROUS_CALLS),
            "secret_keywords":   list(_DEFAULT_SECRET_KEYWORDS),
            "sink_names":        dict(_DEFAULT_SINK_NAMES),
            "feedback_log":      [],
            "update_history":    [],
        }

    def _load(self) -> dict:
        if os.path.exists(self.kb_path):
            try:
                with open(self.kb_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return self._empty()

    def save(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.kb_path)),
                    exist_ok=True)
        self._data["last_updated"] = datetime.now(timezone.utc).isoformat()
        with open(self.kb_path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2)

    # -----------------------------------------------------------------------
    # CVE storage
    # -----------------------------------------------------------------------

    def add_cve(self, record: dict) -> bool:
        cve_id = record.get("cve_id", "")
        if not cve_id:
            return False
        is_new = cve_id not in self._data["cves"]
        self._data["cves"][cve_id] = record
        if is_new:
            self._data["cve_count"] += 1
        return is_new

    def add_cves(self, records: list) -> int:
        new_count = sum(1 for r in records if self.add_cve(r))
        return new_count

    def get_cve(self, cve_id: str) -> Optional[dict]:
        return self._data["cves"].get(cve_id)

    def cves_by_category(self, category: str) -> list:
        return [r for r in self._data["cves"].values()
                if category in r.get("categories", [])]

    def all_cves(self) -> list:
        return list(self._data["cves"].values())

    # -----------------------------------------------------------------------
    # Pattern management
    # -----------------------------------------------------------------------

    def add_pattern(self, pattern: str, category: str,
                    confidence: float = 0.5,
                    source: str = "learned") -> None:
        if pattern not in self._data["patterns"]:
            self._data["patterns"][pattern] = {
                "pattern":    pattern,
                "category":   category,
                "confidence": confidence,
                "source":     source,
                "seen_count": 1,
                "added_at":   datetime.now(timezone.utc).isoformat(),
            }
        else:
            existing = self._data["patterns"][pattern]
            existing["seen_count"] += 1
            # Bayesian-style confidence update
            existing["confidence"] = min(
                0.99,
                existing["confidence"] + (1 - existing["confidence"]) * 0.1
            )

    def get_patterns(self, min_confidence: float = 0.0) -> list:
        return [p for p in self._data["patterns"].values()
                if p["confidence"] >= min_confidence]

    def patterns_by_category(self, category: str,
                              min_confidence: float = 0.3) -> list:
        return [p for p in self._data["patterns"].values()
                if p["category"] == category
                and p["confidence"] >= min_confidence]

    # -----------------------------------------------------------------------
    # Category weights
    # -----------------------------------------------------------------------

    def get_weight(self, category: str) -> float:
        return self._data["category_weights"].get(
            category,
            self._data["category_weights"].get("DEFAULT", 1.0)
        )

    def update_weight(self, category: str, delta: float) -> None:
        current = self.get_weight(category)
        updated = max(0.5, min(2.0, current + delta))
        self._data["category_weights"][category] = round(updated, 4)

    def all_weights(self) -> dict:
        return dict(self._data["category_weights"])

    # -----------------------------------------------------------------------
    # Dynamic detection lists
    # -----------------------------------------------------------------------

    def add_dangerous_call(self, name: str) -> None:
        calls = self._data["dangerous_calls"]
        if name not in calls:
            calls.append(name)

    def add_secret_keyword(self, keyword: str) -> None:
        kws = self._data["secret_keywords"]
        if keyword not in kws:
            kws.append(keyword)

    def add_sink(self, language: str, sink: str) -> None:
        sinks = self._data["sink_names"]
        if language not in sinks:
            sinks[language] = []
        if sink not in sinks[language]:
            sinks[language].append(sink)

    def get_dangerous_calls(self) -> list:
        return list(self._data["dangerous_calls"])

    def get_secret_keywords(self) -> list:
        return list(self._data["secret_keywords"])

    def get_sinks(self, language: str) -> list:
        return list(self._data["sink_names"].get(language, []))

    # -----------------------------------------------------------------------
    # Feedback and continuous learning
    # -----------------------------------------------------------------------

    def record_feedback(self, scan_file: str, findings: list,
                        true_positives: int = -1,
                        false_positives: int = 0) -> None:
        entry = {
            "scan_file":       scan_file,
            "finding_count":   len(findings),
            "true_positives":  true_positives,
            "false_positives": false_positives,
            "categories":      list(set(f.get("category","")
                                       for f in findings)),
            "recorded_at":     datetime.now(timezone.utc).isoformat(),
        }
        self._data["feedback_log"].append(entry)
        # Cap feedback log at 1000 entries
        if len(self._data["feedback_log"]) > 1000:
            self._data["feedback_log"] = self._data["feedback_log"][-1000:]

    # -----------------------------------------------------------------------
    # Version and update history
    # -----------------------------------------------------------------------

    def record_update(self, update_type: str, details: dict) -> str:
        update_id = hashlib.sha256(
            f"{update_type}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]
        entry = {
            "update_id":   update_id,
            "update_type": update_type,
            "details":     details,
            "applied_at":  datetime.now(timezone.utc).isoformat(),
        }
        self._data["update_history"].append(entry)
        self._data["update_count"] += 1
        if len(self._data["update_history"]) > 500:
            self._data["update_history"] = self._data["update_history"][-500:]
        return update_id

    # -----------------------------------------------------------------------
    # Stats
    # -----------------------------------------------------------------------

    def stats(self) -> dict:
        return {
            "version":        self._data.get("version", KB_VERSION),
            "cve_count":      self._data["cve_count"],
            "pattern_count":  len(self._data["patterns"]),
            "update_count":   self._data["update_count"],
            "last_updated":   self._data["last_updated"],
            "feedback_entries": len(self._data["feedback_log"]),
            "category_count": len(self._data["category_weights"]),
            "dangerous_calls": len(self._data["dangerous_calls"]),
            "secret_keywords": len(self._data["secret_keywords"]),
        }

    def export_summary(self) -> dict:
        st = self.stats()
        st["top_patterns"] = sorted(
            self._data["patterns"].values(),
            key=lambda p: p["confidence"],
            reverse=True
        )[:10]
        st["category_weights"] = self.all_weights()
        return st


# ---------------------------------------------------------------------------
# Default detection lists (seed values -- extended by learning)
# ---------------------------------------------------------------------------

_DEFAULT_DANGEROUS_CALLS = {
    "eval", "exec", "compile", "open", "subprocess",
    "os.system", "os.popen", "pickle.loads", "pickle.load",
    "yaml.load", "__import__", "execSync", "exec",
    "marshal.loads", "shelve.open", "importlib.import_module",
}

_DEFAULT_SECRET_KEYWORDS = {
    "password", "secret", "token", "key", "credential",
    "passwd", "pwd", "api_key", "apikey", "auth",
    "private_key", "signing_key", "access_token",
    "refresh_token", "client_secret", "db_password",
}

_DEFAULT_SINK_NAMES = {
    "python": [
        "eval", "exec", "os.system", "os.popen",
        "subprocess.run", "subprocess.call", "subprocess.Popen",
        "pickle.loads", "yaml.load", "open",
        "cursor.execute", "db.execute", "query",
        "marshal.loads",
    ],
    "javascript": [
        "eval", "innerHTML", "document.write",
        "execSync", "exec", "setTimeout", "setInterval",
        "Function", "db.query", "connection.query",
    ],
}
