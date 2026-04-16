"""
MISTCODER  MOD-03  |  Chain Detector
─────────────────────────────────────────────────────────────────────────────
Identifies named, semantically meaningful vulnerability chains from the
attack graph.  A "chain" is a recognised multi-step exploitation pattern
mapped to a real-world attack class.

Chain taxonomy is inspired by:
  • MITRE ATT&CK (TA0001 → TA0009 kill-chain stages)
  • OWASP Top 10 multi-step scenarios
  • CVE compound exploits (e.g. auth bypass + SSRF + SSRF-to-RCE)

Each ChainPattern defines:
  • A sequence of vulnerability kinds that must appear on any viable path
  • A human-readable name and MITRE tactic mapping
  • A risk multiplier applied on top of individual vuln scores

The ChainDetector runs over PathAnalysisResult and annotates every
AttackPath with the chains it matches.
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .path_analyzer import AttackPath, PathAnalysisResult


# ──────────────────────────────────────────────────────────────────────────────
# Chain taxonomy
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ChainPattern:
    """
    A named multi-step exploitation pattern.

    `required_kinds` is an ORDERED list of vulnerability kind tokens that
    must appear (as substrings of node labels) in the path in sequence.
    """

    name:           str
    required_kinds: List[str]
    mitre_tactics:  List[str]
    description:    str
    risk_multiplier: float    = 1.0
    cve_examples:   List[str] = field(default_factory=list)


KNOWN_CHAINS: List[ChainPattern] = [

    ChainPattern(
        name           = "Authentication Bypass → Privilege Escalation",
        required_kinds = ["AUTH", "PRIV_ESC"],
        mitre_tactics  = ["TA0001 Initial Access", "TA0004 Privilege Escalation"],
        description    = "Attacker bypasses authentication controls and immediately "
                         "escalates to a higher privilege context.",
        risk_multiplier = 1.5,
        cve_examples   = ["CVE-2021-27065", "CVE-2020-1472"],
    ),

    ChainPattern(
        name           = "Injection → Data Exfiltration",
        required_kinds = ["INJECTION", "EXFIL"],
        mitre_tactics  = ["TA0001 Initial Access", "TA0010 Exfiltration"],
        description    = "Classic SQL/NoSQL/command injection leading directly to "
                         "sensitive data exfiltration.",
        risk_multiplier = 1.4,
        cve_examples   = ["CVE-2019-0708"],
    ),

    ChainPattern(
        name           = "SSRF → Internal Network Pivot",
        required_kinds = ["SSRF", "INTERNAL_NET"],
        mitre_tactics  = ["TA0005 Defense Evasion", "TA0008 Lateral Movement"],
        description    = "Server-Side Request Forgery used to reach internal services "
                         "normally shielded by the network perimeter.",
        risk_multiplier = 1.6,
        cve_examples   = ["CVE-2019-11581", "CVE-2021-26084"],
    ),

    ChainPattern(
        name           = "Path Traversal → Credential Theft",
        required_kinds = ["PATH_TRAV", "CREDENTIAL"],
        mitre_tactics  = ["TA0006 Credential Access"],
        description    = "Directory traversal used to read credential stores "
                         "(e.g. /etc/passwd, .env files, cloud metadata).",
        risk_multiplier = 1.5,
    ),

    ChainPattern(
        name           = "Deserialization → Remote Code Execution",
        required_kinds = ["DESERIAL", "RCE"],
        mitre_tactics  = ["TA0002 Execution"],
        description    = "Unsafe deserialization of attacker-controlled data "
                         "leading to arbitrary code execution.",
        risk_multiplier = 2.0,
        cve_examples   = ["CVE-2017-9805", "CVE-2015-4852"],
    ),

    ChainPattern(
        name           = "XSS → Session Hijack → Auth Bypass",
        required_kinds = ["XSS", "SESSION", "AUTH"],
        mitre_tactics  = ["TA0006 Credential Access", "TA0001 Initial Access"],
        description    = "Reflected or stored XSS harvests session tokens, "
                         "enabling full account takeover.",
        risk_multiplier = 1.3,
    ),

    ChainPattern(
        name           = "Full Kill-Chain: Entry → Lateral → RCE",
        required_kinds = ["INJECTION", "LATERAL", "RCE"],
        mitre_tactics  = [
            "TA0001 Initial Access",
            "TA0008 Lateral Movement",
            "TA0002 Execution",
        ],
        description    = "Complete multi-stage attack: initial injection, lateral "
                         "movement to another component, culminating in RCE.",
        risk_multiplier = 2.5,
    ),

    ChainPattern(
        name           = "Credential Stuffing → Privilege Escalation → Lateral Movement",
        required_kinds = ["CREDENTIAL", "PRIV_ESC", "LATERAL"],
        mitre_tactics  = [
            "TA0006 Credential Access",
            "TA0004 Privilege Escalation",
            "TA0008 Lateral Movement",
        ],
        description    = "Stolen or weak credentials leveraged to escalate and "
                         "move laterally through the environment.",
        risk_multiplier = 1.8,
    ),

    ChainPattern(
        name           = "File Upload → Server-Side Execution",
        required_kinds = ["UPLOAD", "RCE"],
        mitre_tactics  = ["TA0002 Execution"],
        description    = "Unrestricted file upload allowing the attacker to write "
                         "and execute a web shell or malicious script.",
        risk_multiplier = 1.7,
        cve_examples   = ["CVE-2020-11978"],
    ),

    ChainPattern(
        name           = "IDOR → Data Exfiltration",
        required_kinds = ["IDOR", "EXFIL"],
        mitre_tactics  = ["TA0009 Collection", "TA0010 Exfiltration"],
        description    = "Insecure Direct Object Reference allows enumeration and "
                         "bulk extraction of sensitive records.",
        risk_multiplier = 1.3,
    ),
]


# ──────────────────────────────────────────────────────────────────────────────
# Detected chain result
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class DetectedChain:
    """A confirmed match of a ChainPattern on a specific AttackPath."""

    pattern:         ChainPattern
    path:            AttackPath
    matched_nodes:   List[str]          # node_ids that matched each kind token
    adjusted_score:  float              # exploitability_score × risk_multiplier

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_name":       self.pattern.name,
            "description":      self.pattern.description,
            "mitre_tactics":    self.pattern.mitre_tactics,
            "cve_examples":     self.pattern.cve_examples,
            "risk_multiplier":  self.pattern.risk_multiplier,
            "adjusted_score":   round(self.adjusted_score, 2),
            "path_hops":        self.path.hop_labels(),
            "matched_nodes":    self.matched_nodes,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Chain Detector
# ──────────────────────────────────────────────────────────────────────────────

class ChainDetector:
    """
    Scans every AttackPath in a PathAnalysisResult looking for known
    multi-step exploitation patterns.

    A pattern matches if its required_kinds appear as an ordered subsequence
    of the node labels in the path (does NOT need to be contiguous).
    """

    def __init__(self, patterns: Optional[List[ChainPattern]] = None) -> None:
        self._patterns = patterns or KNOWN_CHAINS

    def detect(self, result: PathAnalysisResult) -> List[DetectedChain]:
        findings: List[DetectedChain] = []

        for path in result.all_paths:
            for pattern in self._patterns:
                match = self._match_pattern(pattern, path)
                if match is not None:
                    adj = path.exploitability_score * pattern.risk_multiplier
                    findings.append(DetectedChain(
                        pattern        = pattern,
                        path           = path,
                        matched_nodes  = match,
                        adjusted_score = min(100.0, adj),
                    ))

        # Deduplicate: keep highest-scoring instance per pattern name
        seen: Dict[str, DetectedChain] = {}
        for dc in findings:
            key = dc.pattern.name
            if key not in seen or dc.adjusted_score > seen[key].adjusted_score:
                seen[key] = dc

        return sorted(seen.values(), key=lambda x: x.adjusted_score, reverse=True)

    def _match_pattern(
        self,
        pattern: ChainPattern,
        path:    AttackPath,
    ) -> Optional[List[str]]:
        """
        Greedy ordered-subsequence match.
        Returns list of matched node_ids in order, or None if no match.
        """
        required = list(pattern.required_kinds)
        matched_ids: List[str] = []
        ri = 0   # index into required list

        for node in path.nodes:
            if ri >= len(required):
                break
            token = required[ri]
            if token.upper() in node.label.upper():
                matched_ids.append(node.node_id)
                ri += 1

        if ri == len(required):
            return matched_ids
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Chain Summary Reporter
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ChainReport:
    """Aggregated chain detection output."""

    detected_chains:   List[DetectedChain]
    unique_tactics:    Set[str]
    max_score:         float
    chain_count:       int

    @classmethod
    def from_chains(cls, chains: List[DetectedChain]) -> "ChainReport":
        tactics: Set[str] = set()
        for dc in chains:
            tactics.update(dc.pattern.mitre_tactics)
        max_score = max((dc.adjusted_score for dc in chains), default=0.0)
        return cls(
            detected_chains = chains,
            unique_tactics  = tactics,
            max_score       = max_score,
            chain_count     = len(chains),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_count":     self.chain_count,
            "max_score":       round(self.max_score, 2),
            "unique_tactics":  sorted(self.unique_tactics),
            "chains":          [dc.to_dict() for dc in self.detected_chains],
        }
