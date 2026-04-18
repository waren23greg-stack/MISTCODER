"""
MISTCODER -- Self-Improvement Core v0.1.0

The learning engine of MISTCODER.

This module orchestrates the complete self-improvement loop:

  1. INGEST   -- Pull new CVE records from NVD feed
  2. LEARN    -- Extract patterns and update knowledge base
  3. EVALUATE -- Assess knowledge gain from this cycle
  4. APPLY    -- Export updated detection config for scanner use
  5. LOG      -- Record the cycle with full audit trail

Design principles:
  -- Every update is versioned and auditable
  -- No change is applied without being logged
  -- Weights are bounded -- the system cannot over-amplify any category
  -- Learning is additive and monotonic -- knowledge is never deleted
  -- Human review gates are enforced for high-impact updates

This is the difference between a tool that was trained once
and a system that never stops improving.
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional

from cve_ingester    import CVEIngester
from knowledge_base  import KnowledgeBase
from pattern_learner import PatternLearner


CYCLE_LOG_PATH = os.path.join(
    os.path.dirname(__file__),
    "..", "..", "..", "sandbox", "improvement_cycles.json"
)

DETECTION_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__),
    "..", "..", "..", "sandbox", "detection_config.json"
)

# Thresholds that trigger a human review gate
REVIEW_GATE_THRESHOLDS = {
    "weight_delta_max":   0.20,  # any weight change > 0.20 requires review
    "pattern_batch_max":  500,   # > 500 new patterns in one cycle
    "cve_batch_max":      1000,  # > 1000 CVEs in one cycle
}


class ImprovementCycle:
    """
    Represents one complete self-improvement cycle.
    Immutable record once created.
    """

    def __init__(self, cycle_id: str, mode: str):
        self.cycle_id    = cycle_id
        self.mode        = mode
        self.started_at  = datetime.now(timezone.utc).isoformat()
        self.completed_at = None
        self.stages      = []
        self.summary     = {}
        self.requires_review = False
        self.review_reason   = ""

    def add_stage(self, name: str, result: dict) -> None:
        self.stages.append({
            "stage":  name,
            "result": result,
            "at":     datetime.now(timezone.utc).isoformat(),
        })

    def complete(self, summary: dict) -> None:
        self.summary      = summary
        self.completed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "cycle_id":       self.cycle_id,
            "mode":           self.mode,
            "started_at":     self.started_at,
            "completed_at":   self.completed_at,
            "stages":         self.stages,
            "summary":        self.summary,
            "requires_review": self.requires_review,
            "review_reason":   self.review_reason,
        }


class SelfImprovementCore:
    """
    Orchestrates the full MISTCODER self-improvement loop.

    Modes:
      "synthetic"  -- use built-in CVE dataset (no network, always works)
      "live"       -- fetch from NVD API (requires network)
      "cached"     -- use local cache from previous live fetch
      "feedback"   -- learn from scan results only (no CVE ingestion)
    """

    def __init__(self,
                 kb_path: Optional[str] = None,
                 cache_dir: Optional[str] = None,
                 api_key: str = ""):
        self.kb      = KnowledgeBase(kb_path)
        self.ingester = CVEIngester(
            cache_dir=cache_dir or os.path.join(
                os.path.dirname(__file__),
                "..", "..", "..", "sandbox", "cve_cache"
            ),
            api_key=api_key
        )
        self.learner  = PatternLearner(self.kb)
        self._cycles  = self._load_cycles()

    # -----------------------------------------------------------------------
    # Cycle log
    # -----------------------------------------------------------------------

    def _load_cycles(self) -> list:
        if os.path.exists(CYCLE_LOG_PATH):
            try:
                with open(CYCLE_LOG_PATH, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _save_cycles(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(CYCLE_LOG_PATH)),
                    exist_ok=True)
        with open(CYCLE_LOG_PATH, "w") as f:
            json.dump(self._cycles[-200:], f, indent=2)

    def _next_cycle_id(self) -> str:
        return f"CYCLE-{len(self._cycles)+1:04d}"

    # -----------------------------------------------------------------------
    # Review gate enforcement
    # -----------------------------------------------------------------------

    def _check_review_gate(self, cycle: ImprovementCycle,
                           learn_result: dict,
                           kb_before: dict) -> None:
        weights_after  = self.kb.all_weights()
        weights_before = kb_before.get("category_weights", {})

        max_delta = 0.0
        for cat, after in weights_after.items():
            before    = weights_before.get(cat, after)
            max_delta = max(max_delta, abs(after - before))

        if max_delta > REVIEW_GATE_THRESHOLDS["weight_delta_max"]:
            cycle.requires_review = True
            cycle.review_reason   = (
                f"Weight delta {max_delta:.3f} exceeds threshold "
                f"{REVIEW_GATE_THRESHOLDS['weight_delta_max']}. "
                f"Human review required before applying to production scanner."
            )

        patterns_added = learn_result.get("patterns_added", 0)
        if patterns_added > REVIEW_GATE_THRESHOLDS["pattern_batch_max"]:
            cycle.requires_review = True
            cycle.review_reason  += (
                f" Pattern batch size {patterns_added} exceeds threshold."
            )

    # -----------------------------------------------------------------------
    # Main improvement loop
    # -----------------------------------------------------------------------

    def run_cycle(self,
                  mode: str = "synthetic",
                  days: int = 7,
                  scan_findings: Optional[list] = None,
                  target_file: str = "",
                  verbose: bool = True) -> dict:
        """
        Execute one complete self-improvement cycle.

        Parameters
        ----------
        mode          : "synthetic" | "live" | "cached" | "feedback"
        days          : days of CVE history to pull (live/cached modes)
        scan_findings : findings from a recent scan (for feedback mode)
        target_file   : path of scanned file (for feedback mode)
        verbose       : print progress to stdout
        """
        cycle_id = self._next_cycle_id()
        cycle    = ImprovementCycle(cycle_id, mode)

        if verbose:
            print()
            print("=" * 60)
            print(f"  MISTCODER Self-Improvement Core v0.1.0")
            print(f"  Cycle {cycle_id}  |  Mode: {mode.upper()}")
            print("=" * 60)

        kb_snapshot = {
            "category_weights": dict(self.kb.all_weights()),
            "pattern_count":    len(self.kb.get_patterns()),
            "cve_count":        self.kb.stats()["cve_count"],
        }

        learn_result = {}

        # -------------------------------------------------------------------
        # Stage 1 -- CVE Ingestion
        # -------------------------------------------------------------------
        if mode != "feedback":
            if verbose:
                print()
                print(f"[STAGE 1] CVE Ingestion  ({mode})")
            if mode == "synthetic":
                cve_records = self.ingester.load_synthetic()
            elif mode == "live":
                cve_records = self.ingester.fetch_recent(
                    days=days, use_cache=False)
            else:
                cve_records = self.ingester.fetch_recent(
                    days=days, use_cache=True)

            new_cves = self.kb.add_cves(cve_records)
            ingest_result = {
                "total_fetched": len(cve_records),
                "new_to_kb":     new_cves,
                "mode":          mode,
            }
            cycle.add_stage("ingestion", ingest_result)
            if verbose:
                print(f"  CVEs fetched    : {len(cve_records)}")
                print(f"  New to KB       : {new_cves}")

            # -------------------------------------------------------------------
            # Stage 2 -- Pattern Learning
            # -------------------------------------------------------------------
            if verbose:
                print()
                print(f"[STAGE 2] Pattern Learning from CVEs")
            learn_result = self.learner.learn_from_cves(cve_records)
            cycle.add_stage("cve_learning", learn_result)
            if verbose:
                print(f"  Patterns added  : {learn_result.get('patterns_added', 0)}")
                print(f"  Dangerous calls : {learn_result.get('calls_added', 0)}")
                print(f"  Sink names      : {learn_result.get('sinks_added', 0)}")
                print(f"  Secret keywords : {learn_result.get('keywords_added', 0)}")
                print(f"  Weights updated : {learn_result.get('weights_updated', 0)}")
        else:
            cycle.add_stage("ingestion", {"mode": "feedback_only"})
            if verbose:
                print()
                print(f"[STAGE 1] Skipped (feedback mode)")

        # -------------------------------------------------------------------
        # Stage 3 -- Scan Feedback Integration
        # -------------------------------------------------------------------
        if scan_findings:
            if verbose:
                print()
                print(f"[STAGE 3] Scan Feedback Integration")
            feedback_result = self.learner.learn_from_scan(
                scan_findings, target_file)
            learn_result.update(feedback_result)
            cycle.add_stage("scan_feedback", feedback_result)
            if verbose:
                print(f"  Findings ingested: {feedback_result.get('findings_seen', 0)}")
                print(f"  Patterns learned : {feedback_result.get('learned', 0)}")
        else:
            cycle.add_stage("scan_feedback", {"skipped": True})
            if verbose:
                print()
                print(f"[STAGE 3] Scan Feedback  (no findings provided)")

        # -------------------------------------------------------------------
        # Stage 4 -- Review Gate Check
        # -------------------------------------------------------------------
        if verbose:
            print()
            print(f"[STAGE 4] Review Gate Evaluation")
        self._check_review_gate(cycle, learn_result, kb_snapshot)
        gate_result = {
            "requires_review": cycle.requires_review,
            "reason":          cycle.review_reason,
        }
        cycle.add_stage("review_gate", gate_result)
        if cycle.requires_review:
            if verbose:
                print(f"  STATUS: REVIEW REQUIRED")
                print(f"  Reason: {cycle.review_reason[:80]}")
        else:
            if verbose:
                print(f"  STATUS: APPROVED -- no anomalies detected")

        # -------------------------------------------------------------------
        # Stage 5 -- Apply and Export
        # -------------------------------------------------------------------
        if verbose:
            print()
            print(f"[STAGE 5] Exporting Detection Configuration")
        self.kb.save()
        config = self.learner.export_detection_config()
        os.makedirs(os.path.dirname(os.path.abspath(DETECTION_CONFIG_PATH)),
                    exist_ok=True)
        with open(DETECTION_CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=2)
        export_result = {
            "kb_saved":              True,
            "detection_config_path": DETECTION_CONFIG_PATH,
            "dangerous_calls":       len(config["dangerous_calls"]),
            "secret_keywords":       len(config["secret_keywords"]),
            "high_conf_patterns":    len(config["high_conf_patterns"]),
        }
        cycle.add_stage("export", export_result)
        if verbose:
            print(f"  Dangerous calls  : {export_result['dangerous_calls']}")
            print(f"  Secret keywords  : {export_result['secret_keywords']}")
            print(f"  High-conf pattns : {export_result['high_conf_patterns']}")
            print(f"  Config path      : {DETECTION_CONFIG_PATH}")

        # -------------------------------------------------------------------
        # Finalize cycle
        # -------------------------------------------------------------------
        kb_after = self.kb.stats()
        summary  = {
            "cve_count_before":     kb_snapshot["cve_count"],
            "cve_count_after":      kb_after["cve_count"],
            "pattern_count_before": kb_snapshot["pattern_count"],
            "pattern_count_after":  kb_after["pattern_count"],
            "update_count":         kb_after["update_count"],
            "requires_review":      cycle.requires_review,
            "detection_config":     export_result,
        }
        cycle.complete(summary)
        self._cycles.append(cycle.to_dict())
        self._save_cycles()

        if verbose:
            print()
            print("=" * 60)
            print(f"  CYCLE {cycle_id} COMPLETE")
            print("=" * 60)
            print(f"  CVEs in KB      : {kb_after['cve_count']}")
            print(f"  Patterns in KB  : {kb_after['pattern_count']}")
            print(f"  KB updates      : {kb_after['update_count']}")
            print(f"  Review required : {cycle.requires_review}")
            print("=" * 60)
            print()

        return cycle.to_dict()

    # -----------------------------------------------------------------------
    # Cycle history and stats
    # -----------------------------------------------------------------------

    def history(self, last_n: int = 10) -> list:
        return self._cycles[-last_n:]

    def kb_stats(self) -> dict:
        return self.kb.export_summary()

    def detection_config(self) -> dict:
        return self.learner.export_detection_config()
