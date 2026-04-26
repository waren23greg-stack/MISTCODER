"""
MISTCODER -- CVSS Risk Scorer v0.1.0

Implements CVSS 3.1 Base Score calculation from first principles.
Extends standard CVSS with MISTCODER context scoring:
  -- Chain amplification  (chained vulns score higher)
  -- Reachability weight  (unreachable findings discounted)
  -- Asset criticality    (auth/crypto/db nodes weighted up)
  -- Temporal decay       (older CVE references decay slightly)

Output schema:
  {
    "scores":       [ ScoredFinding ],
    "aggregate":    AggregateScore,
    "risk_vector":  str,
    "risk_label":   str,
    "metadata":     { ... }
  }
"""

import math
import json
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# CVSS 3.1 Metric values
# ---------------------------------------------------------------------------

# Attack Vector
AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
# Attack Complexity
AC = {"L": 0.77, "H": 0.44}
# Privileges Required (adjusted for Scope change)
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED   = {"N": 0.85, "L": 0.68, "H": 0.50}
# User Interaction
UI = {"N": 0.85, "R": 0.62}
# Scope
SC = {"U": "UNCHANGED", "C": "CHANGED"}
# CIA Impact
CIA = {"N": 0.00, "L": 0.22, "H": 0.56}

# Severity bands (CVSS 3.1)
SEVERITY_BANDS = [
    (0.0,  0.0,  "NONE"),
    (0.1,  3.9,  "LOW"),
    (4.0,  6.9,  "MEDIUM"),
    (7.0,  8.9,  "HIGH"),
    (9.0, 10.0,  "CRITICAL"),
]

# ---------------------------------------------------------------------------
# MISTCODER context weights
# ---------------------------------------------------------------------------

# Asset criticality multiplier by node type / category
ASSET_WEIGHT = {
    "authentication":    1.30,
    "authorization":     1.25,
    "crypto":            1.25,
    "database":          1.20,
    "secret_flag":       1.35,
    "SECRET_EXPOSURE":   1.35,
    "DANGEROUS_CALL":    1.20,
    "PROCESS_EXEC":      1.25,
    "INJECTION":         1.15,
    "XSS":               1.10,
    "default":           1.00,
}

# Chain amplification -- chained findings get this multiplier
CHAIN_AMPLIFIER = 1.20

# Reachability discount -- findings not on any attack path
UNREACHABLE_DISCOUNT = 0.70

# ---------------------------------------------------------------------------
# CVSS 3.1 vector presets for common MISTCODER finding categories
# ---------------------------------------------------------------------------

CATEGORY_VECTORS = {
    "DANGEROUS_CALL": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S":  "C", "C":  "H", "I":  "H", "A":  "H",
        "description": "Remote code execution via dangerous call"
    },
    "COMMAND_INJECTION": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S":  "C", "C":  "H", "I":  "H", "A":  "H",
        "description": "OS command injection"
    },
    "SQL_INJECTION": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S":  "U", "C":  "H", "I":  "H", "A":  "L",
        "description": "SQL injection — data exfil / manipulation"
    },
    "XSS": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S":  "C", "C":  "L", "I":  "L", "A":  "N",
        "description": "Cross-site scripting"
    },
    "PATH_TRAVERSAL": {
        "AV": "N", "AC": "L", "PR": "L", "UI": "N",
        "S":  "U", "C":  "H", "I":  "N", "A":  "N",
        "description": "Path traversal — file read"
    },
    "SECRET_EXPOSURE": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S":  "C", "C":  "H", "I":  "H", "A":  "H",
        "description": "Hardcoded or exposed credential"
    },
    "HARDCODED_SECRET": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S":  "C", "C":  "H", "I":  "H", "A":  "H",
        "description": "Hardcoded credential in source"
    },
    "INSECURE_DESERIAL": {
        "AV": "N", "AC": "H", "PR": "N", "UI": "N",
        "S":  "U", "C":  "H", "I":  "H", "A":  "H",
        "description": "Insecure deserialization"
    },
    "MISSING_AUTHZ": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S":  "U", "C":  "H", "I":  "H", "A":  "N",
        "description": "Missing authorization check"
    },
    "PRIVILEGE_ESC": {
        "AV": "L", "AC": "L", "PR": "L", "UI": "N",
        "S":  "C", "C":  "H", "I":  "H", "A":  "H",
        "description": "Privilege escalation"
    },
    "SSRF": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S":  "C", "C":  "H", "I":  "L", "A":  "N",
        "description": "Server-side request forgery"
    },
    "TAINT_FLOW": {
        "AV": "N", "AC": "H", "PR": "N", "UI": "N",
        "S":  "U", "C":  "H", "I":  "L", "A":  "N",
        "description": "Unsanitized taint flow to sink"
    },
    "OPEN_REDIRECT": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S":  "U", "C":  "L", "I":  "L", "A":  "N",
        "description": "Open redirect"
    },
    "EXCEPTION_SWALLOW": {
        "AV": "N", "AC": "H", "PR": "N", "UI": "N",
        "S":  "U", "C":  "L", "I":  "N", "A":  "N",
        "description": "Exception swallowed — information loss"
    },
    "DEFAULT": {
        "AV": "N", "AC": "H", "PR": "L", "UI": "N",
        "S":  "U", "C":  "L", "I":  "L", "A":  "N",
        "description": "Generic finding"
    },
}


# ---------------------------------------------------------------------------
# CVSS 3.1 calculation
# ---------------------------------------------------------------------------

def _cvss_base_score(av: str, ac: str, pr: str, ui: str,
                     s: str, c: str, i: str, a: str) -> float:
    """
    Compute CVSS 3.1 Base Score from metric strings.
    Returns float in [0.0, 10.0].
    """
    scope_changed = (s.upper() == "C")
    av_val  = AV.get(av.upper(), 0.85)
    ac_val  = AC.get(ac.upper(), 0.77)
    pr_val  = (PR_CHANGED if scope_changed else PR_UNCHANGED).get(pr.upper(), 0.85)
    ui_val  = UI.get(ui.upper(), 0.85)
    c_val   = CIA.get(c.upper(), 0.22)
    i_val   = CIA.get(i.upper(), 0.22)
    a_val   = CIA.get(a.upper(), 0.22)

    # ISC (Impact Sub-Score)
    iss = 1.0 - (1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val)

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    if scope_changed:
        raw = min(1.08 * (impact + exploitability), 10.0)
    else:
        raw = min(impact + exploitability, 10.0)

    # Round up to 1 decimal (CVSS 3.1 spec)
    return math.ceil(raw * 10) / 10


def _cvss_vector_string(av: str, ac: str, pr: str, ui: str,
                        s: str, c: str, i: str, a: str) -> str:
    return (f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}"
            f"/S:{s}/C:{c}/I:{i}/A:{a}")


def _severity_label(score: float) -> str:
    for low, high, label in SEVERITY_BANDS:
        if low <= score <= high:
            return label
    return "NONE"


# ---------------------------------------------------------------------------
# Context scoring
# ---------------------------------------------------------------------------

def _asset_weight(category: str, node_type: str = "") -> float:
    for key in (category, node_type):
        if key in ASSET_WEIGHT:
            return ASSET_WEIGHT[key]
    return ASSET_WEIGHT["default"]


def _context_score(base: float, category: str,
                   in_chain: bool = False,
                   reachable: bool = True,
                   node_type: str = "") -> float:
    """
    Apply MISTCODER context modifiers to base CVSS score.
    Result is capped at 10.0.
    """
    score = base
    score *= _asset_weight(category, node_type)
    if in_chain:
        score *= CHAIN_AMPLIFIER
    if not reachable:
        score *= UNREACHABLE_DISCOUNT
    return round(min(score, 10.0), 2)


# ---------------------------------------------------------------------------
# Score a single finding
# ---------------------------------------------------------------------------

def score_finding(finding: dict,
                  in_chain: bool = False,
                  reachable: bool = True) -> dict:
    """
    Score a single MOD-02 finding dict.
    Returns a ScoredFinding dict.
    """
    category = finding.get("category", "DEFAULT")
    vector   = CATEGORY_VECTORS.get(category, CATEGORY_VECTORS["DEFAULT"])

    av = vector.get("AV", "N")
    ac = vector.get("AC", "H")
    pr = vector.get("PR", "L")
    ui = vector.get("UI", "N")
    s  = vector.get("S",  "U")
    c  = vector.get("C",  "L")
    i  = vector.get("I",  "L")
    a  = vector.get("A",  "N")

    base_score    = _cvss_base_score(av, ac, pr, ui, s, c, i, a)
    context_score = _context_score(base_score, category,
                                   in_chain, reachable,
                                   finding.get("type", ""))
    vector_str    = _cvss_vector_string(av, ac, pr, ui, s, c, i, a)
    severity      = _severity_label(context_score)

    return {
        "finding_id":        finding.get("id", "--"),
        "category":          category,
        "description":       finding.get("description", "--"),
        "line":              finding.get("line"),
        "cvss_base_score":   base_score,
        "context_score":     context_score,
        "severity":          severity,
        "cvss_vector":       vector_str,
        "modifiers": {
            "in_chain":      in_chain,
            "reachable":     reachable,
            "asset_weight":  _asset_weight(category),
            "chain_amp":     CHAIN_AMPLIFIER if in_chain else 1.0,
            "reach_disc":    UNREACHABLE_DISCOUNT if not reachable else 1.0,
        },
        "vector_detail": {
            "attack_vector":         av,
            "attack_complexity":     ac,
            "privileges_required":   pr,
            "user_interaction":      ui,
            "scope":                 s,
            "confidentiality":       c,
            "integrity":             i,
            "availability":          a,
        }
    }


# ---------------------------------------------------------------------------
# Aggregate score
# ---------------------------------------------------------------------------

def _aggregate(scored_findings: list) -> dict:
    """
    Compound aggregate formula:
    aggregate = 1 - product(1 - score_i / 10)
    Bounded to [0, 10]. Grows with every additional finding.
    """
    if not scored_findings:
        return {"score": 0.0, "label": "NONE", "finding_count": 0}

    product = 1.0
    for sf in scored_findings:
        product *= (1.0 - sf["context_score"] / 10.0)

    raw   = (1.0 - product) * 10.0
    score = round(min(raw, 10.0), 2)
    return {
        "score":         score,
        "label":         _severity_label(score),
        "finding_count": len(scored_findings),
        "critical":      sum(1 for s in scored_findings if s["severity"] == "CRITICAL"),
        "high":          sum(1 for s in scored_findings if s["severity"] == "HIGH"),
        "medium":        sum(1 for s in scored_findings if s["severity"] == "MEDIUM"),
        "low":           sum(1 for s in scored_findings if s["severity"] == "LOW"),
    }


def _risk_vector(aggregate: dict, findings: list) -> str:
    """
    Compact MISTCODER risk vector string.
    Format: MIST/AG:<score>/C:<n>/H:<n>/M:<n>/L:<n>/FC:<finding_count>
    """
    return (
        f"MIST/AG:{aggregate['score']}"
        f"/C:{aggregate.get('critical', 0)}"
        f"/H:{aggregate.get('high', 0)}"
        f"/M:{aggregate.get('medium', 0)}"
        f"/L:{aggregate.get('low', 0)}"
        f"/FC:{aggregate['finding_count']}"
    )


def _risk_label(score: float) -> str:
    labels = [
        (9.0, "CRITICAL -- Immediate remediation required. "
              "Active exploitation is probable."),
        (7.0, "HIGH -- Urgent remediation required. "
              "Significant breach risk identified."),
        (4.0, "MEDIUM -- Remediation recommended in current cycle. "
              "Exploitability requires specific conditions."),
        (0.1, "LOW -- Remediation at discretion. "
              "Limited exploitability under normal conditions."),
        (0.0, "NONE -- No significant risk identified."),
    ]
    for threshold, label in labels:
        if score >= threshold:
            return label
    return "NONE"


# ---------------------------------------------------------------------------
# CVSSScorer -- main entry point
# ---------------------------------------------------------------------------

class CVSSScorer:
    """
    MOD scoring entry point.
    Accepts MOD-02 findings + optional MOD-03 chain/path data.
    Returns fully scored risk assessment.
    """

    def score(self,
              findings: list,
              chains: Optional[list] = None,
              attack_paths: Optional[list] = None) -> dict:
        """
        Score all findings with CVSS 3.1 + MISTCODER context modifiers.

        Parameters
        ----------
        findings      : list  MOD-02 finding dicts
        chains        : list  MOD-03 chain records (optional)
        attack_paths  : list  MOD-03 attack path records (optional)

        Returns
        -------
        dict  complete scoring report
        """
        chains       = chains or []
        attack_paths = attack_paths or []

        # Build sets for context lookup
        chained_ids   = self._chained_finding_ids(chains)
        reachable_ids = self._reachable_finding_ids(attack_paths, findings)

        scored = []
        for finding in findings:
            fid      = finding.get("id", "")
            in_chain = fid in chained_ids
            reachable = fid in reachable_ids or not attack_paths
            scored.append(score_finding(finding, in_chain, reachable))

        scored.sort(key=lambda x: x["context_score"], reverse=True)

        aggregate  = _aggregate(scored)
        risk_vec   = _risk_vector(aggregate, findings)
        risk_label = _risk_label(aggregate["score"])

        return {
            "scores":      scored,
            "aggregate":   aggregate,
            "risk_vector": risk_vec,
            "risk_label":  risk_label,
            "metadata": {
                "scorer":       "CVSSScorer v0.1.0",
                "standard":     "CVSS 3.1",
                "extensions":   [
                    "chain_amplification",
                    "reachability_weighting",
                    "asset_criticality",
                ],
                "scored_at":    datetime.now(timezone.utc).isoformat(),
                "finding_count": len(findings),
                "chain_count":   len(chains),
            }
        }

    def _chained_finding_ids(self, chains: list) -> set:
        ids = set()
        for chain in chains:
            for link in chain.get("links", []):
                ids.add(link)
        return ids

    def _reachable_finding_ids(self, attack_paths: list,
                               findings: list) -> set:
        if not attack_paths:
            return {f.get("id", "") for f in findings}
        ids = set()
        for path in attack_paths:
            for node_id in path.get("nodes", []):
                ids.add(node_id)
        return ids

    def export_json(self, result: dict, output_path: str) -> None:
        import os
        os.makedirs(os.path.dirname(os.path.abspath(output_path)),
                    exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"[SCORER] Risk report exported to {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import os

    if len(sys.argv) < 2:
        print("Usage: python cvss_scorer.py <findings_json> "
              "[chains_json] [--export output.json]")
        sys.exit(1)

    with open(sys.argv[1], "r", encoding="utf-8") as f:
        findings_doc = json.load(f)

    findings = findings_doc.get("findings", [])
    chains   = []
    export   = None

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--export" and i + 1 < len(sys.argv):
            export = sys.argv[i + 1]; i += 2
        elif not sys.argv[i].startswith("--"):
            with open(sys.argv[i], "r", encoding="utf-8") as f:
                chains_doc = json.load(f)
            chains = chains_doc.get("chains", [])
            i += 1
        else:
            i += 1

    scorer = CVSSScorer()
    result = scorer.score(findings, chains)
    agg    = result["aggregate"]

    print(f"\n[SCORER] MISTCODER CVSS Risk Scorer v0.1.0")
    print(f"[SCORER] Findings    : {agg['finding_count']}")
    print("=" * 60)
    print(f"  AGGREGATE SCORE  : {agg['score']} / 10.0")
    print(f"  SEVERITY         : {agg['label']}")
    print(f"  RISK VECTOR      : {result['risk_vector']}")
    print("-" * 60)
    print(f"  {result['risk_label']}")
    print("-" * 60)
    print(f"  Critical : {agg.get('critical', 0)}")
    print(f"  High     : {agg.get('high', 0)}")
    print(f"  Medium   : {agg.get('medium', 0)}")
    print(f"  Low      : {agg.get('low', 0)}")
    print("-" * 60)
    print("  TOP FINDINGS BY CONTEXT SCORE:")
    for sf in result["scores"][:5]:
        print(f"  [{sf['severity']:8s}] {sf['context_score']:5.2f}  "
              f"{sf['category']:25s}  line={sf['line'] or '--'}")
    print("=" * 60)

    if export:
        scorer.export_json(result, export)
