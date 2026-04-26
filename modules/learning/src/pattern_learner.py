"""
MISTCODER -- Pattern Learner v0.1.0

Extracts reusable vulnerability detection patterns from CVE records
and scan results. Updates the Knowledge Base with new signals.

Learning occurs at two levels:
  1. CVE-level  -- patterns extracted from CVE descriptions and metadata
  2. Scan-level -- patterns extracted from real scan findings (feedback loop)

The learner answers the question:
  "What does MISTCODER not yet know how to find,
   and what can it learn from what it has already seen?"
"""

import re
from collections import defaultdict, Counter
from typing import Optional
from knowledge_base import KnowledgeBase


# Minimum CVE frequency for a pattern to be promoted to high-confidence
MIN_PATTERN_FREQUENCY = 2

# Confidence increment per additional CVE observation
CONFIDENCE_INCREMENT   = 0.08

# Known dangerous function name patterns extracted from CVE descriptions
FUNC_PATTERNS = [
    r'\b(eval|exec|execfile|compile)\s*\(',
    r'\bos\.(system|popen|execvp?e?)\s*\(',
    r'\bsubprocess\.(run|call|Popen|check_output)\s*\(',
    r'\bpickle\.(loads?|dumps?)\s*\(',
    r'\byaml\.load\s*\(',
    r'\bmarshal\.(loads?|dumps?)\s*\(',
    r'\b__import__\s*\(',
    r'\bgetattr\s*\(',
    r'\bimportlib\.import_module\s*\(',
    r'\bexecSync\s*\(',
    r'innerHTML\s*=',
    r'document\.write\s*\(',
    r'\.query\s*\(\s*["\']?\s*(?:SELECT|INSERT|UPDATE|DELETE)',
    r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*{',
    r'%\s*(?:SELECT|INSERT|UPDATE|DELETE)',
    r'\.format\s*\(\s*\)',
]

# Sink patterns by language
SINK_PATTERNS = {
    "python": {
        r'\beval\s*\(':              ("eval", "DANGEROUS_CALL"),
        r'\bexec\s*\(':              ("exec", "DANGEROUS_CALL"),
        r'\bos\.system\s*\(':        ("os.system", "COMMAND_INJECTION"),
        r'\bos\.popen\s*\(':         ("os.popen", "COMMAND_INJECTION"),
        r'\bsubprocess\.':           ("subprocess", "COMMAND_INJECTION"),
        r'\bpickle\.loads?\s*\(':    ("pickle.loads", "INSECURE_DESERIAL"),
        r'\byaml\.load\s*\(':        ("yaml.load", "INSECURE_DESERIAL"),
        r'\bcursor\.execute\s*\(':   ("cursor.execute", "SQL_INJECTION"),
        r'SELECT.*%s':               ("string-sql", "SQL_INJECTION"),
        r'SELECT.*\.format':         ("format-sql", "SQL_INJECTION"),
        r'f["\'].*SELECT':           ("fstring-sql", "SQL_INJECTION"),
        r'\bopen\s*\(':              ("open", "PATH_TRAVERSAL"),
    },
    "javascript": {
        r'\beval\s*\(':              ("eval", "DANGEROUS_CALL"),
        r'\.innerHTML\s*=':          ("innerHTML", "XSS"),
        r'document\.write\s*\(':     ("document.write", "XSS"),
        r'\bexecSync\s*\(':          ("execSync", "COMMAND_INJECTION"),
        r'\bFunction\s*\(':          ("Function", "DANGEROUS_CALL"),
        r'db\.query\s*\(':           ("db.query", "SQL_INJECTION"),
    },
}

# Secret variable name patterns
SECRET_VAR_PATTERNS = [
    r'(?:^|\s)(password|passwd|pwd)\s*=',
    r'(?:^|\s)(api_key|apikey|api_secret)\s*=',
    r'(?:^|\s)(secret_?key|signing_?key)\s*=',
    r'(?:^|\s)(access_?token|auth_?token|refresh_?token)\s*=',
    r'(?:^|\s)(private_?key|client_?secret)\s*=',
    r'(?:^|\s)(db_?pass(?:word)?|database_?pass(?:word)?)\s*=',
    r'(?:^|\s)(auth_?key|encryption_?key)\s*=',
]


class PatternLearner:
    """
    Extracts vulnerability detection patterns from CVE records
    and scan feedback. Updates the KnowledgeBase with new intelligence.
    """

    def __init__(self, kb: KnowledgeBase):
        self.kb = kb

    # -----------------------------------------------------------------------
    # Learn from CVE records
    # -----------------------------------------------------------------------

    def learn_from_cves(self, cve_records: list) -> dict:
        """
        Process a list of CVE records and extract patterns into the KB.
        Returns a learning summary.
        """
        patterns_added    = 0
        calls_added       = 0
        sinks_added       = 0
        keywords_added    = 0
        weights_updated   = 0
        category_counter  = Counter()

        for rec in cve_records:
            categories = rec.get("categories", [])
            patterns   = rec.get("patterns", [])
            cvss_score = rec.get("cvss_score", 0.0)
            desc       = rec.get("description", "")
            cwe_ids    = rec.get("cwe_ids", [])

            # Count category frequency for weight adjustment
            for cat in categories:
                category_counter[cat] += 1

            # Add extracted patterns to KB
            base_conf = min(0.9, cvss_score / 10.0)
            for pattern in patterns:
                for cat in categories or ["DEFAULT"]:
                    self.kb.add_pattern(pattern, cat,
                                        confidence=base_conf,
                                        source="cve")
                    patterns_added += 1

            # Extract and add dangerous function names from description
            for func_pattern in FUNC_PATTERNS:
                matches = re.findall(func_pattern, desc, re.IGNORECASE)
                for match in matches:
                    name = match.strip("( ").lower()
                    if len(name) > 2:
                        self.kb.add_dangerous_call(name)
                        calls_added += 1

            # Extract sink names from description
            for lang, sinks in SINK_PATTERNS.items():
                for sink_pattern, (sink_name, cat) in sinks.items():
                    if re.search(sink_pattern, desc, re.IGNORECASE):
                        self.kb.add_sink(lang, sink_name)
                        sinks_added += 1

            # Extract secret keywords
            for kw_pattern in SECRET_VAR_PATTERNS:
                matches = re.findall(kw_pattern, desc, re.IGNORECASE)
                for match in matches:
                    self.kb.add_secret_keyword(match.lower())
                    keywords_added += 1

        # Adjust category weights based on CVE frequency
        total_cves = len(cve_records)
        if total_cves > 0:
            for cat, count in category_counter.items():
                frequency = count / total_cves
                if frequency > 0.3:
                    delta = 0.05
                elif frequency > 0.15:
                    delta = 0.02
                else:
                    delta = 0.0
                if delta > 0:
                    self.kb.update_weight(cat, delta)
                    weights_updated += 1

        update_id = self.kb.record_update("cve_learning", {
            "cve_count":       len(cve_records),
            "patterns_added":  patterns_added,
            "calls_added":     calls_added,
            "sinks_added":     sinks_added,
            "keywords_added":  keywords_added,
            "weights_updated": weights_updated,
        })

        return {
            "update_id":       update_id,
            "cves_processed":  len(cve_records),
            "patterns_added":  patterns_added,
            "calls_added":     calls_added,
            "sinks_added":     sinks_added,
            "keywords_added":  keywords_added,
            "weights_updated": weights_updated,
        }

    # -----------------------------------------------------------------------
    # Learn from scan results (feedback loop)
    # -----------------------------------------------------------------------

    def learn_from_scan(self, scan_findings: list,
                        target_file: str = "",
                        confirmed_tps: Optional[list] = None) -> dict:
        """
        Learn from scan results.
        Confirmed true positives reinforce the patterns that found them.
        All findings contribute to category frequency statistics.
        """
        if not scan_findings:
            return {"learned": 0}

        confirmed_ids = set(confirmed_tps or [])
        learned       = 0

        cat_counts = Counter(f.get("category", "") for f in scan_findings)

        for finding in scan_findings:
            cat         = finding.get("category", "DEFAULT")
            finding_id  = finding.get("id", "")
            is_confirmed = finding_id in confirmed_ids

            # Confirmed true positives get a larger confidence boost
            if is_confirmed:
                self.kb.update_weight(cat, +0.03)
                learned += 1
            else:
                # All findings get a small positive signal
                self.kb.update_weight(cat, +0.005)

        # Record feedback
        self.kb.record_feedback(
            scan_file       = target_file,
            findings        = scan_findings,
            true_positives  = len(confirmed_ids),
            false_positives = 0,
        )

        update_id = self.kb.record_update("scan_feedback", {
            "scan_file":     target_file,
            "finding_count": len(scan_findings),
            "confirmed_tps": len(confirmed_ids),
            "learned":       learned,
        })

        return {
            "update_id":     update_id,
            "findings_seen": len(scan_findings),
            "learned":       learned,
        }

    # -----------------------------------------------------------------------
    # Pattern export for scanner injection
    # -----------------------------------------------------------------------

    def export_detection_config(self) -> dict:
        """
        Export the current learned detection configuration.
        This dict is consumed by the scanner modules to improve detection.
        """
        return {
            "dangerous_calls":  self.kb.get_dangerous_calls(),
            "secret_keywords":  self.kb.get_secret_keywords(),
            "sinks_python":     self.kb.get_sinks("python"),
            "sinks_javascript": self.kb.get_sinks("javascript"),
            "category_weights": self.kb.all_weights(),
            "high_conf_patterns": [
                p["pattern"] for p in
                self.kb.get_patterns(min_confidence=0.7)
            ],
            "generated_at": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat(),
        }
