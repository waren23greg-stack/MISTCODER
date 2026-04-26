"""
MISTCODER  MOD-03  |  Reasoning Core  — Crown Jewel
─────────────────────────────────────────────────────────────────────────────

  "Give me a list of what's broken and I'll give you a list of how you die."

  The Reasoning Core is the intelligence layer of MISTCODER.  It takes raw
  vulnerability findings from MOD-01/MOD-02 and reasons about them the way
  a skilled penetration tester would:

    1. Build the attack surface as a property graph
    2. Find every path an attacker could walk
    3. Detect multi-step exploitation chains by pattern
    4. Score and prioritise everything using a CVSS-aware risk model
    5. Return a self-contained ReasoningResult that drives the report

  The Reasoning Core owns no I/O.  It is a pure transformation:
      findings: List[Dict] → ReasoningResult

  Pipeline position:
      MOD-01 Parser  →  MOD-02 Analysis  →  [MOD-03 Reasoning]  →  Report

─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from attack_graph   import AttackGraph, AttackGraphBuilder
from path_analyzer  import PathAnalyzer, PathAnalysisResult
from chain_detector import ChainDetector, ChainReport
from risk_scorer    import RiskScorer, TargetRisk


# ──────────────────────────────────────────────────────────────────────────────
# Reasoning configuration
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ReasoningConfig:
    """Tuning knobs for the Reasoning Core pipeline."""

    target_name:   str   = "unknown_target"
    max_paths:     int   = 200       # max attack paths to enumerate
    max_depth:     int   = 20        # max hops per path
    min_confidence: float = 0.0      # filter findings below this confidence


# ──────────────────────────────────────────────────────────────────────────────
# Reasoning result
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ReasoningResult:
    """
    The complete output of one Reasoning Core run.

    Every field is serialisable to JSON for downstream consumption by
    the Report Generator and Pipeline CLI.
    """

    config:        ReasoningConfig
    graph:         AttackGraph
    path_result:   PathAnalysisResult
    chain_report:  ChainReport
    target_risk:   TargetRisk

    elapsed_ms:    float = 0.0
    warnings:      List[str] = field(default_factory=list)

    # ── convenience accessors ─────────────────────────────────────────────────

    @property
    def risk_level(self) -> str:
        return self.target_risk.risk_level

    @property
    def aggregate_score(self) -> float:
        return self.target_risk.aggregate_score

    @property
    def chain_count(self) -> int:
        return self.chain_report.chain_count

    @property
    def viable_paths(self) -> int:
        return self.path_result.total_viable_paths

    @property
    def most_critical_path_hops(self) -> List[str]:
        cp = self.path_result.most_critical_path
        return cp.hop_labels() if cp else []

    # ── serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "meta": {
                "target":     self.config.target_name,
                "elapsed_ms": round(self.elapsed_ms, 1),
                "warnings":   self.warnings,
            },
            "attack_graph": self.graph.to_dict(),
            "path_analysis": self.path_result.to_dict(),
            "chain_report":  self.chain_report.to_dict(),
            "target_risk":   self.target_risk.to_dict(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    # ── terminal pretty-print ─────────────────────────────────────────────────

    def print_summary(self) -> None:
        width = 72
        SEP  = "─" * width
        DSEP = "═" * width

        rl_colors = {
            "CRITICAL": "\033[91m",
            "HIGH":     "\033[93m",
            "MEDIUM":   "\033[33m",
            "LOW":      "\033[92m",
            "MINIMAL":  "\033[94m",
        }
        RESET = "\033[0m"
        rl_c  = rl_colors.get(self.risk_level, "")

        print(f"\n{DSEP}")
        print(f"  MISTCODER  ·  MOD-03 Reasoning Core  ·  {self.config.target_name}")
        print(DSEP)

        # Graph stats
        print(f"\n  ATTACK GRAPH")
        print(f"  {SEP}")
        print(f"  Nodes            : {self.graph.node_count}")
        print(f"  Edges            : {self.graph.edge_count}")
        print(f"  Has cycles       : {self.graph.has_cycles()}")
        print(f"  Sources          : {len(self.graph.sources())}")
        print(f"  Sinks            : {len(self.graph.sinks())}")

        # Path analysis
        print(f"\n  PATH ANALYSIS")
        print(f"  {SEP}")
        print(f"  Viable paths     : {self.viable_paths}")
        print(f"  Unreachable vulns: {len(self.path_result.unreachable_nodes)}")
        cp = self.path_result.most_critical_path
        if cp:
            print(f"  Most critical    : score {cp.exploitability_score:.1f}")
            hops = " → ".join(cp.hop_labels())
            # Wrap long hop chains
            if len(hops) > 60:
                hops = "\n" + "\n".join(
                    "    " + h for h in cp.hop_labels()
                )
            print(f"    {hops}")

        # Chains
        print(f"\n  VULNERABILITY CHAINS DETECTED  ({self.chain_count})")
        print(f"  {SEP}")
        if self.chain_report.detected_chains:
            for dc in self.chain_report.detected_chains[:5]:
                bar = "█" * int(dc.adjusted_score / 5)
                print(f"  [{bar:<20}] {dc.adjusted_score:5.1f}  {dc.pattern.name}")
        else:
            print("  No multi-step chains detected.")

        # Risk verdict
        print(f"\n  RISK VERDICT")
        print(f"  {SEP}")
        print(f"  {rl_c}▶ {self.risk_level:8s}  {self.aggregate_score:.1f} / 10.0{RESET}")

        # Top attack surface
        print(f"\n  TOP ATTACK SURFACE")
        print(f"  {SEP}")
        for line in self.target_risk.top_attack_surface:
            print(f"  • {line}")

        # Remediation order
        print(f"\n  REMEDIATION ORDER  (top 8)")
        print(f"  {SEP}")
        for r in self.target_risk.remediation_order[:8]:
            loc = f"{r.file_path}:{r.line_start}" if r.file_path else "N/A"
            print(f"  [{r.remediation_priority:>3}] {r.label:<30}  {r.severity:<8}  "
                  f"score={r.final_score:<4}  {loc}")

        print(f"\n  Elapsed: {self.elapsed_ms:.0f} ms")
        print(f"{DSEP}\n")


# ──────────────────────────────────────────────────────────────────────────────
# The Reasoning Core
# ──────────────────────────────────────────────────────────────────────────────

class ReasoningCore:
    """
    Entry point for MOD-03.

    Orchestrates the four sub-systems in a deterministic, testable pipeline:

        AttackGraphBuilder  →  PathAnalyzer  →  ChainDetector  →  RiskScorer
    """

    def __init__(self, config: Optional[ReasoningConfig] = None) -> None:
        self._config = config or ReasoningConfig()

    def reason(self, findings: List[Dict[str, Any]]) -> ReasoningResult:
        """
        Primary entry point.

        Args:
            findings: List of finding dicts from MOD-02 Analysis Engine.
                      Each must contain at minimum: id, kind, severity,
                      file_path, line_start, confidence, cwe_ids, metadata.

        Returns:
            ReasoningResult – fully populated, ready for reporting.
        """
        t0 = time.perf_counter()
        warnings: List[str] = []

        # ── Filter by confidence threshold ────────────────────────────────────
        filtered = [
            f for f in findings
            if f.get("confidence", 1.0) >= self._config.min_confidence
        ]
        if len(filtered) < len(findings):
            warnings.append(
                f"{len(findings) - len(filtered)} findings filtered "
                f"below confidence threshold {self._config.min_confidence}."
            )

        # ── Stage 1: Build the Attack Graph ───────────────────────────────────
        builder = AttackGraphBuilder(target_name=self._config.target_name)
        builder.ingest(filtered)
        graph = builder.build()

        if graph.is_empty():
            warnings.append("Attack graph is empty – no findings to reason about.")

        # ── Stage 2: Path Analysis ────────────────────────────────────────────
        analyzer    = PathAnalyzer(
            graph,
            max_paths = self._config.max_paths,
            max_depth = self._config.max_depth,
        )
        path_result = analyzer.analyze()

        if path_result.total_viable_paths == 0:
            warnings.append("No viable attack paths found from source to sink.")

        # ── Stage 3: Chain Detection ──────────────────────────────────────────
        detector     = ChainDetector()
        chains       = detector.detect(path_result)
        chain_report = ChainReport.from_chains(chains)

        # ── Stage 4: Risk Scoring ─────────────────────────────────────────────
        scorer      = RiskScorer(graph, path_result, chain_report)
        target_risk = scorer.score()

        elapsed = (time.perf_counter() - t0) * 1000.0

        return ReasoningResult(
            config       = self._config,
            graph        = graph,
            path_result  = path_result,
            chain_report = chain_report,
            target_risk  = target_risk,
            elapsed_ms   = elapsed,
            warnings     = warnings,
        )

    def reason_from_json(self, json_str: str) -> ReasoningResult:
        """Convenience wrapper – parses MOD-02 JSON output directly."""
        findings = json.loads(json_str)
        if isinstance(findings, dict):
            findings = findings.get("findings", [])
        return self.reason(findings)
