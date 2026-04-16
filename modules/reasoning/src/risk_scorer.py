"""
MISTCODER  MOD-03  |  Risk Scorer
─────────────────────────────────────────────────────────────────────────────
Produces a final, human-readable risk verdict for the entire scan target.

Scoring model  (CVSS 3.1 inspired, extended for chain-awareness):

  Base Score factors:
    • Attack Vector       (Network / Adjacent / Local / Physical)
    • Attack Complexity   (Low / High)
    • Privileges Required (None / Low / High)
    • User Interaction    (None / Required)
    • Scope               (Changed / Unchanged)
    • Confidentiality, Integrity, Availability impact (H/M/L/N)

  MISTCODER extensions:
    • Chain Multiplier    – chains amplify the base score
    • Blast Radius Bonus  – nodes that reach many sinks score higher
    • Reachability Factor – unreachable vulns are discounted

Final output:
    • Per-finding RiskScore
    • Aggregate TargetRiskScore
    • Prioritised remediation list
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .attack_graph  import AttackGraph, AttackNode, Severity
from .path_analyzer import PathAnalysisResult
from .chain_detector import ChainReport


# ──────────────────────────────────────────────────────────────────────────────
# CVSS-style enumerations
# ──────────────────────────────────────────────────────────────────────────────

class AttackVector(str, Enum):
    NETWORK  = "NETWORK"
    ADJACENT = "ADJACENT"
    LOCAL    = "LOCAL"
    PHYSICAL = "PHYSICAL"

class AttackComplexity(str, Enum):
    LOW  = "LOW"
    HIGH = "HIGH"

class PrivilegesRequired(str, Enum):
    NONE = "NONE"
    LOW  = "LOW"
    HIGH = "HIGH"

class Impact(str, Enum):
    NONE = "NONE"
    LOW  = "LOW"
    HIGH = "HIGH"


AV_SCORE  = {AttackVector.NETWORK: 0.85, AttackVector.ADJACENT: 0.62,
             AttackVector.LOCAL:   0.55, AttackVector.PHYSICAL:  0.20}
AC_SCORE  = {AttackComplexity.LOW: 0.77, AttackComplexity.HIGH: 0.44}
PR_SCORE  = {PrivilegesRequired.NONE: 0.85, PrivilegesRequired.LOW: 0.62,
             PrivilegesRequired.HIGH: 0.27}
IMP_SCORE = {Impact.NONE: 0.00, Impact.LOW: 0.22, Impact.HIGH: 0.56}


# ──────────────────────────────────────────────────────────────────────────────
# Per-finding risk
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class FindingRisk:
    node_id:            str
    label:              str
    file_path:          Optional[str]
    line_start:         Optional[int]
    severity:           str
    cvss_base:          float          # 0.0 – 10.0
    chain_amplified:    float          # CVSS × chain multiplier
    blast_radius:       int
    reachable:          bool
    final_score:        float          # 0.0 – 10.0, rounded
    remediation_priority: int          # 1 = fix first

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id":              self.node_id,
            "label":                self.label,
            "file_path":            self.file_path,
            "line_start":           self.line_start,
            "severity":             self.severity,
            "cvss_base":            round(self.cvss_base, 1),
            "chain_amplified":      round(self.chain_amplified, 1),
            "blast_radius":         self.blast_radius,
            "reachable":            self.reachable,
            "final_score":          round(self.final_score, 1),
            "remediation_priority": self.remediation_priority,
        }


@dataclass
class TargetRisk:
    """Aggregate risk verdict for the whole scan target."""

    aggregate_score:    float          # 0.0 – 10.0
    risk_level:         str            # CRITICAL / HIGH / MEDIUM / LOW / MINIMAL
    finding_risks:      List[FindingRisk]
    top_attack_surface: List[str]      # top-N most dangerous nodes
    remediation_order:  List[FindingRisk]
    summary:            str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "aggregate_score":    round(self.aggregate_score, 2),
            "risk_level":         self.risk_level,
            "summary":            self.summary,
            "top_attack_surface": self.top_attack_surface,
            "findings":           [f.to_dict() for f in self.finding_risks],
            "remediation_order":  [f.to_dict() for f in self.remediation_order],
        }


# ──────────────────────────────────────────────────────────────────────────────
# Risk Scorer
# ──────────────────────────────────────────────────────────────────────────────

class RiskScorer:
    """
    Consumes the full MOD-03 analysis outputs and produces TargetRisk.

    Usage:
        scorer = RiskScorer(graph, path_result, chain_report)
        target = scorer.score()
    """

    # Default CVSS-like assumptions for static analysis context
    _DEFAULT_AV = AttackVector.NETWORK
    _DEFAULT_AC = AttackComplexity.LOW
    _DEFAULT_PR = PrivilegesRequired.NONE

    # Chain name → multiplier (from ChainDetector)
    # Applied to CVSS score of every node participating in that chain
    _CHAIN_MULT_CAP = 1.5   # cap so we don't exceed 10.0

    def __init__(
        self,
        graph:         AttackGraph,
        path_result:   PathAnalysisResult,
        chain_report:  ChainReport,
    ) -> None:
        self._g      = graph
        self._pr     = path_result
        self._cr     = chain_report

    def score(self) -> TargetRisk:
        finding_risks = self._score_findings()
        aggregate     = self._aggregate(finding_risks)
        risk_level    = self._classify(aggregate)
        top_surface   = self._top_attack_surface(finding_risks, n=5)
        remediation   = sorted(finding_risks, key=lambda r: r.remediation_priority)
        summary       = self._generate_summary(aggregate, risk_level, finding_risks)

        return TargetRisk(
            aggregate_score    = aggregate,
            risk_level         = risk_level,
            finding_risks      = finding_risks,
            top_attack_surface = top_surface,
            remediation_order  = remediation,
            summary            = summary,
        )

    # ── Scoring helpers ───────────────────────────────────────────────────────

    def _score_findings(self) -> List[FindingRisk]:
        results: List[FindingRisk] = []

        # Build node→chain-multiplier map
        chain_mults: Dict[str, float] = {}
        for dc in self._cr.detected_chains:
            for nid in dc.matched_nodes:
                mult = chain_mults.get(nid, 1.0)
                chain_mults[nid] = max(mult, dc.pattern.risk_multiplier)

        for node in self._g.nodes():
            cvss  = self._cvss_base(node)
            mult  = min(self._CHAIN_MULT_CAP, chain_mults.get(node.node_id, 1.0))
            chain_amp = min(10.0, cvss * mult)

            blast     = self._pr.blast_radius.get(node.node_id, 0)
            reachable = self._pr.reachability_scores.get(node.node_id, 0.0) > 0.0

            # Final score: amplified base, discounted if unreachable
            final = chain_amp * (1.0 if reachable else 0.3)
            final = round(min(10.0, final), 1)

            results.append(FindingRisk(
                node_id             = node.node_id,
                label               = node.label,
                file_path           = node.file_path,
                line_start          = node.line_start,
                severity            = node.severity.value,
                cvss_base           = cvss,
                chain_amplified     = chain_amp,
                blast_radius        = blast,
                reachable           = reachable,
                final_score         = final,
                remediation_priority = 0,   # set below
            ))

        # Assign remediation priority (rank by final_score desc, break ties by blast_radius)
        ranked = sorted(results, key=lambda r: (r.final_score, r.blast_radius), reverse=True)
        for i, r in enumerate(ranked, 1):
            r.remediation_priority = i

        return results

    def _cvss_base(self, node: AttackNode) -> float:
        """
        Simplified CVSS 3.1 base score computation.

        We derive CIA impact from severity, and use static AV/AC/PR
        defaults appropriate for a web-application static analysis context.
        """
        # Derive impact from severity
        imp_map = {
            Severity.CRITICAL: Impact.HIGH,
            Severity.HIGH:     Impact.HIGH,
            Severity.MEDIUM:   Impact.LOW,
            Severity.LOW:      Impact.LOW,
            Severity.INFO:     Impact.NONE,
        }
        imp = imp_map.get(node.severity, Impact.LOW)

        # ISC sub-score (confidentiality + integrity + availability)
        c_imp = IMP_SCORE[imp]
        i_imp = IMP_SCORE[imp]
        a_imp = IMP_SCORE[Impact.LOW if imp == Impact.HIGH else Impact.NONE]

        iss = 1 - ((1 - c_imp) * (1 - i_imp) * (1 - a_imp))

        # Impact sub-score (scope unchanged simplification)
        isc = 6.42 * iss

        # Exploitability sub-score
        av = AV_SCORE[self._DEFAULT_AV]
        ac = AC_SCORE[self._DEFAULT_AC]
        pr = PR_SCORE[self._DEFAULT_PR]
        ui = 0.85  # No user interaction assumed
        esc = 8.22 * av * ac * pr * ui

        if iss <= 0:
            return 0.0

        base = min(10.0, (isc + esc) / 2.0)
        # Apply confidence discount
        return base * node.confidence

    def _aggregate(self, risks: List[FindingRisk]) -> float:
        """
        Aggregate individual scores into one target score.

        Uses the "critical path" formula:
            aggregate = max_score × (1 - ∏(1 - score_i/10))
        This grows with each additional finding but is bounded by 10.
        """
        if not risks:
            return 0.0
        product = 1.0
        for r in risks:
            if r.reachable and r.final_score > 0:
                product *= (1 - r.final_score / 10)
        combined = 1 - product
        max_score = max((r.final_score for r in risks), default=0.0)
        # Blend: 70% combined surface, 30% single worst case
        aggregate = 0.70 * (combined * 10) + 0.30 * max_score
        return min(10.0, aggregate)

    @staticmethod
    def _classify(score: float) -> str:
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        if score >= 1.0: return "LOW"
        return "MINIMAL"

    @staticmethod
    def _top_attack_surface(risks: List[FindingRisk], n: int) -> List[str]:
        reachable = [r for r in risks if r.reachable]
        top = sorted(reachable, key=lambda r: r.final_score, reverse=True)[:n]
        return [f"{r.label} ({r.severity}) — score {r.final_score}" for r in top]

    @staticmethod
    def _generate_summary(
        score:  float,
        level:  str,
        risks:  List[FindingRisk],
    ) -> str:
        reachable_count = sum(1 for r in risks if r.reachable)
        chain_vulns     = sum(1 for r in risks if r.chain_amplified > r.cvss_base + 0.5)
        worst = next((r for r in sorted(risks, key=lambda r: r.final_score, reverse=True)
                      if r.reachable), None)

        lines = [
            f"MISTCODER Risk Assessment — Level: {level}  ({score:.1f}/10)",
            "",
            f"  {len(risks)} findings detected, {reachable_count} reachable from attack surface.",
            f"  {chain_vulns} findings amplified by multi-step exploitation chains.",
        ]
        if worst:
            lines.append(
                f"  Highest priority: {worst.label} at {worst.file_path}:{worst.line_start}"
                f" (score {worst.final_score})."
            )
        lines += [
            "",
            "  Recommendation: Address all CRITICAL and HIGH findings before deployment.",
            "  Focus remediation on the top-5 attack surface nodes identified above.",
        ]
        return "\n".join(lines)
