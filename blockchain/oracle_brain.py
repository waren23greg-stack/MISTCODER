# blockchain/oracle_brain.py
# MISTCODER Threat-Native Blockchain
# OracleBrain — Self-Improving Threat Intelligence Core
# Neural-first: 60% ThreatNet + 40% pattern memory fusion

from __future__ import annotations

import json
import hashlib
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

SANDBOX = Path(__file__).resolve().parent.parent / "sandbox"

KB_PATH   = SANDBOX / "oracle_knowledge.json"
CO_PATH   = SANDBOX / "oracle_cooccurrence.json"
INC_PATH  = SANDBOX / "oracle_incubation.json"
VEL_PATH  = SANDBOX / "oracle_velocity.json"
SIG_PATH  = SANDBOX / "oracle_signatures.json"
LOG_PATH  = SANDBOX / "oracle_brain_log.json"

INCUBATION_PROMOTIONS_NEEDED = 3
CONFIDENCE_DECAY_RATE        = 0.02
MAX_CONFIDENCE               = 0.99
MIN_CONFIDENCE               = 0.50
CO_OCCURRENCE_WEIGHT         = 0.05

SEED_KNOWLEDGE = {
    "eval_exec": {
        "cves": ["CVE-2023-27043", "CVE-2022-48560"],
        "confidence": 0.94, "verdict": "CONFIRMED", "sightings": 1,
        "first_seen": "2026-01-01", "last_seen": "2026-01-01",
        "associated_cwes": ["CWE-94", "CWE-78"],
        "description": "Arbitrary code execution via eval/exec on untrusted input"
    },
    "sql_query": {
        "cves": ["CVE-2023-23397", "CVE-2022-32250"],
        "confidence": 0.91, "verdict": "CONFIRMED", "sightings": 1,
        "first_seen": "2026-01-01", "last_seen": "2026-01-01",
        "associated_cwes": ["CWE-89"],
        "description": "SQL injection via unparameterised query construction"
    },
    "hardcoded_secret": {
        "cves": ["CVE-2022-1471"],
        "confidence": 0.88, "verdict": "CONFIRMED", "sightings": 1,
        "first_seen": "2026-01-01", "last_seen": "2026-01-01",
        "associated_cwes": ["CWE-312", "CWE-798"],
        "description": "Hardcoded credentials exposed in source"
    },
    "path_traversal": {
        "cves": ["CVE-2023-44487"],
        "confidence": 0.85, "verdict": "CONFIRMED", "sightings": 1,
        "first_seen": "2026-01-01", "last_seen": "2026-01-01",
        "associated_cwes": ["CWE-22"],
        "description": "Directory traversal via unsanitised file path"
    },
    "deserialization": {
        "cves": ["CVE-2022-42889"],
        "confidence": 0.89, "verdict": "CONFIRMED", "sightings": 1,
        "first_seen": "2026-01-01", "last_seen": "2026-01-01",
        "associated_cwes": ["CWE-502"],
        "description": "Unsafe deserialization of untrusted data"
    },
    "weak_hash": {
        "cves": ["CVE-2023-36665"],
        "confidence": 0.86, "verdict": "CONFIRMED", "sightings": 1,
        "first_seen": "2026-01-01", "last_seen": "2026-01-01",
        "associated_cwes": ["CWE-327", "CWE-328"],
        "description": "Weak cryptographic hash algorithm in use"
    },
    "file_path": {
        "cves": ["CVE-2023-44487"],
        "confidence": 0.82, "verdict": "CONFIRMED", "sightings": 1,
        "first_seen": "2026-01-01", "last_seen": "2026-01-01",
        "associated_cwes": ["CWE-22", "CWE-73"],
        "description": "Unvalidated file path used in file system operation"
    },
}


class OracleBrain:

    def __init__(self, verbose: bool = True):
        self.verbose    = verbose
        self._threatnet = None
        SANDBOX.mkdir(exist_ok=True)

        self.knowledge    = self._load(KB_PATH,  SEED_KNOWLEDGE)
        self.cooccurrence = self._load(CO_PATH,  {})
        self.incubation   = self._load(INC_PATH, {})
        self.velocity     = self._load(VEL_PATH, {})
        self.signatures   = self._load(SIG_PATH, {})
        self.log          = self._load(LOG_PATH, {"decisions": []})
        self.scan_number  = self._infer_scan_number()

        self._log(f"OracleBrain online — scan #{self.scan_number} — "
                  f"{len(self.knowledge)} known patterns")

        # Boot ThreatNet quietly
        try:
            from blockchain.threatnet import ThreatNet
            self._threatnet = ThreatNet()
            if self._threatnet.trained and self.verbose:
                print("[ORACLE BRAIN] ThreatNet loaded — neural inference active")
        except Exception as e:
            self._log(f"ThreatNet unavailable: {e}")

    # ══════════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ══════════════════════════════════════════════════════════════════════

    def evaluate(self, finding_id: str, steps: list, score: float) -> dict:
        """Neural-first evaluation fused with adaptive pattern memory."""
        self._log(f"Evaluating {finding_id} | steps={steps} | score={score}")

        # ── Step 0: ThreatNet neural inference (primary) ──────────────────
        neural_result = None
        if self._threatnet and self._threatnet.trained:
            try:
                neural_result = self._threatnet.predict(
                    steps=steps, score=score, stealth=0.75, novelty=0.5
                )
                self._log(
                    f"ThreatNet: {neural_result['verdict']} "
                    f"conf={neural_result['confidence']}"
                )
            except Exception as e:
                self._log(f"ThreatNet inference error: {e}")

        # ── Step 1: Pattern matching (secondary / fallback) ───────────────
        match_key, match_data = self._match_knowledge(steps)
        co_boost              = self._cooccurrence_boost(steps)
        base_confidence       = match_data["confidence"] if match_data else 0.70
        decayed               = self._apply_decay(match_key, base_confidence)
        pattern_confidence    = min(MAX_CONFIDENCE, decayed + co_boost)

        # ── Step 2: Fuse neural + pattern (60/40) ─────────────────────────
        if neural_result and neural_result.get("method") == "neural":
            final_confidence = (
                0.60 * neural_result["confidence"] +
                0.40 * pattern_confidence
            )
            verdict = neural_result["verdict"]
        else:
            final_confidence = pattern_confidence
            verdict = match_data["verdict"] if match_data else "NOVEL"

        # CVE refs
        if match_data:
            cve_refs = match_data["cves"]
        else:
            verdict_inc, cve_refs = self._check_incubation(steps, score)
            if not neural_result:
                verdict = verdict_inc

        # Confidence floor guard
        if final_confidence < MIN_CONFIDENCE:
            verdict = "DISPUTED"
        final_confidence = min(MAX_CONFIDENCE, final_confidence)

        # ── Steps 3-8 ────────────────────────────────────────────────────
        prediction = self._predict_associated(steps)
        signature  = self._build_signature(finding_id, steps, score)
        reasoning  = self._build_reasoning(
            finding_id, match_key, final_confidence,
            co_boost, verdict, cve_refs, prediction
        )
        if neural_result:
            reasoning += f" | ThreatNet {neural_result['confidence']:.3f}"

        self._update_knowledge(match_key, steps, final_confidence, cve_refs)
        self._update_cooccurrence(steps)
        self._update_velocity(steps)
        self._store_signature(signature, finding_id, steps, score, verdict)
        self._save_all()

        result = {
            "confidence": round(final_confidence, 4),
            "verdict"   : verdict,
            "cve_refs"  : cve_refs,
            "prediction": prediction,
            "reasoning" : reasoning,
            "signature" : signature[:16],
            "neural"    : neural_result
        }

        if self.verbose:
            self._print_evaluation(finding_id, result)

        return result

    def end_scan(self):
        self._promote_incubations()
        self._analyse_velocity()
        self.scan_number += 1
        self._save_all()
        self._print_scan_summary()

    def brain_report(self) -> dict:
        return {
            "scan_number"       : self.scan_number,
            "known_patterns"    : len(self.knowledge),
            "cooccurrence_pairs": sum(
                1 for v in self.cooccurrence.values()
                if isinstance(v, dict)
            ),
            "incubating_novel"  : len(self.incubation),
            "signatures_logged" : len(self.signatures),
            "velocity_tracked"  : len(self.velocity),
            "rising_threats"    : self._get_rising_threats(),
            "top_confidence"    : self._top_confidence_patterns(),
            "neural_active"     : bool(
                self._threatnet and self._threatnet.trained
            )
        }

    # ══════════════════════════════════════════════════════════════════════
    # INTELLIGENCE LAYERS
    # ══════════════════════════════════════════════════════════════════════

    def _match_knowledge(self, steps):
        best_key, best_data, best_score = None, None, 0
        for step in steps:
            step_lower = step.lower().replace(" ", "_").replace("-", "_")
            for key, data in self.knowledge.items():
                if key in step_lower or step_lower in key:
                    s = len(key)
                    if s > best_score:
                        best_score = s
                        best_key   = key
                        best_data  = data
        return best_key, best_data

    def _cooccurrence_boost(self, steps):
        boost, pairs_found = 0.0, 0
        for i, step_a in enumerate(steps):
            for step_b in steps[i+1:]:
                key = self._pair_key(step_a, step_b)
                if key in self.cooccurrence:
                    count = self.cooccurrence[key].get("count", 0)
                    boost += min(0.15, count * CO_OCCURRENCE_WEIGHT)
                    pairs_found += 1
        if pairs_found > 0:
            boost = boost / pairs_found
        return round(min(0.20, boost), 4)

    def _update_cooccurrence(self, steps):
        today = self._today()
        for i, step_a in enumerate(steps):
            for step_b in steps[i+1:]:
                key = self._pair_key(step_a, step_b)
                if key not in self.cooccurrence:
                    self.cooccurrence[key] = {
                        "step_a": step_a, "step_b": step_b,
                        "count": 0, "first_seen": today, "last_seen": today
                    }
                self.cooccurrence[key]["count"]    += 1
                self.cooccurrence[key]["last_seen"]  = today

    def _apply_decay(self, match_key, base_confidence):
        if not match_key or match_key not in self.knowledge:
            return base_confidence
        last_seen = self.knowledge[match_key].get("last_seen", self._today())
        try:
            last_dt = datetime.strptime(last_seen, "%Y-%m-%d")
            months  = max(0, (datetime.now() - last_dt).days / 30.0)
            decayed = base_confidence * ((1 - CONFIDENCE_DECAY_RATE) ** months)
            return max(MIN_CONFIDENCE, round(decayed, 4))
        except Exception:
            return base_confidence

    def _check_incubation(self, steps, score):
        fingerprint = self._fingerprint_steps(steps)
        today       = self._today()
        if fingerprint not in self.incubation:
            self.incubation[fingerprint] = {
                "steps": steps, "sightings": 1,
                "first_seen": today, "last_seen": today,
                "scores": [score], "status": "INCUBATING"
            }
            self._log(f"Novel pattern incubated: {fingerprint[:12]}...")
            return "NOVEL", []
        record = self.incubation[fingerprint]
        record["sightings"] += 1
        record["last_seen"]  = today
        record["scores"].append(score)
        if record["sightings"] >= INCUBATION_PROMOTIONS_NEEDED:
            return "CONFIRMED", []
        return "NOVEL", []

    def _promote_incubations(self):
        promoted = []
        for fp, record in self.incubation.items():
            if (record["sightings"] >= INCUBATION_PROMOTIONS_NEEDED
                    and record["status"] == "INCUBATING"):
                steps   = record["steps"]
                avg_sc  = sum(record["scores"]) / len(record["scores"])
                new_key = "_".join(
                    s.lower().replace(" ", "_")
                    for s in steps[:2] if not s.startswith("CWE")
                ) or f"novel_pattern_{fp[:8]}"
                self.knowledge[new_key] = {
                    "cves": [], "confidence": 0.75, "verdict": "CONFIRMED",
                    "sightings": record["sightings"],
                    "first_seen": record["first_seen"],
                    "last_seen": record["last_seen"],
                    "associated_cwes": [s for s in steps if s.startswith("CWE")],
                    "description": (
                        f"ORACLE-discovered. Promoted after "
                        f"{record['sightings']} sightings. "
                        f"Avg score: {avg_sc:.2f}."
                    ),
                    "source": "ORACLE_SELF_AUTHORED"
                }
                record["status"] = "PROMOTED"
                promoted.append(new_key)
                self._log(f"PROMOTED: {new_key} → knowledge base")
        if promoted and self.verbose:
            print(f"\n[ORACLE BRAIN] ★ PROMOTED {len(promoted)} pattern(s):")
            for p in promoted:
                print(f"  + {p}")

    def _update_velocity(self, steps):
        today = self._today()
        for step in steps:
            if step not in self.velocity:
                self.velocity[step] = {
                    "appearances": [], "trend": "STABLE", "last_seen": today
                }
            self.velocity[step]["appearances"].append(self.scan_number)
            self.velocity[step]["last_seen"] = today

    def _analyse_velocity(self):
        for step, data in self.velocity.items():
            appearances = data["appearances"]
            if len(appearances) < 2:
                data["trend"] = "STABLE"
                continue
            mid    = len(appearances) // 2
            recent = len(appearances[mid:])
            older  = len(appearances[:mid])
            if recent > older:
                data["trend"] = "RISING"
            elif recent < older:
                data["trend"] = "FALLING"
            else:
                data["trend"] = "STABLE"

    def _get_rising_threats(self):
        return [k for k, v in self.velocity.items()
                if v.get("trend") == "RISING"]

    def _predict_associated(self, steps):
        predictions = {}
        for step in steps:
            step_lower = step.lower().replace(" ", "_")
            for key, data in self.cooccurrence.items():
                if not isinstance(data, dict):
                    continue
                step_a = data.get("step_a", "").lower().replace(" ", "_")
                step_b = data.get("step_b", "").lower().replace(" ", "_")
                other  = None
                if step_lower in step_a or step_a in step_lower:
                    other = data.get("step_b")
                elif step_lower in step_b or step_b in step_lower:
                    other = data.get("step_a")
                if other and other not in steps:
                    predictions[other] = predictions.get(other, 0) + \
                                         data.get("count", 0)
        sorted_preds = sorted(predictions.items(), key=lambda x: -x[1])
        return [p[0] for p in sorted_preds[:3]]

    def _build_signature(self, finding_id, steps, score):
        cwes  = sorted([s for s in steps if s.startswith("CWE")])
        calls = sorted([s for s in steps if not s.startswith("CWE")])
        band  = ("CRITICAL" if score >= 8.0 else
                 "HIGH"     if score >= 6.0 else
                 "MEDIUM"   if score >= 4.0 else "LOW")
        raw = json.dumps({"cwes": cwes, "calls": calls, "band": band},
                         sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()

    def _store_signature(self, signature, finding_id, steps, score, verdict):
        if signature not in self.signatures:
            self.signatures[signature] = {
                "first_seen": self._today(), "sightings": 0,
                "finding_ids": [], "verdict": verdict,
                "steps": steps, "score_range": [score, score]
            }
        rec = self.signatures[signature]
        rec["sightings"]    += 1
        rec["finding_ids"].append(finding_id)
        rec["score_range"][0] = min(rec["score_range"][0], score)
        rec["score_range"][1] = max(rec["score_range"][1], score)

    def _update_knowledge(self, match_key, steps, confidence, cve_refs):
        if not match_key or match_key not in self.knowledge:
            return
        entry = self.knowledge[match_key]
        entry["sightings"] = entry.get("sightings", 0) + 1
        entry["last_seen"] = self._today()
        current = entry["confidence"]
        entry["confidence"] = min(MAX_CONFIDENCE,
                                  round(current + (MAX_CONFIDENCE - current) * 0.03, 4))
        for step in steps:
            if step.startswith("CWE") and \
               step not in entry.get("associated_cwes", []):
                entry.setdefault("associated_cwes", []).append(step)
        for cve in cve_refs:
            if cve not in entry.get("cves", []):
                entry.setdefault("cves", []).append(cve)

    # ══════════════════════════════════════════════════════════════════════
    # DISPLAY
    # ══════════════════════════════════════════════════════════════════════

    def _print_evaluation(self, finding_id, result):
        symbol = {"CONFIRMED": "✓", "NOVEL": "?", "DISPUTED": "✗"}.get(
            result["verdict"], "·")
        print(f"[ORACLE BRAIN] {symbol} {finding_id}")
        print(f"  Confidence : {result['confidence']} | "
              f"Verdict: {result['verdict']}")
        if result["cve_refs"]:
            print(f"  CVE refs   : {', '.join(result['cve_refs'])}")
        else:
            print(f"  CVE refs   : none — novel pattern")
        if result.get("prediction"):
            print(f"  Prediction : also expect → {result['prediction']}")
        print(f"  Signature  : {result['signature']}")
        print(f"  Reasoning  : {result['reasoning']}")
        print()

    def _print_scan_summary(self):
        report = self.brain_report()
        print()
        print("  ┌─ ORACLE BRAIN SCAN SUMMARY ─────────────────────")
        print(f"  │  Scan number     : #{report['scan_number']}")
        print(f"  │  Known patterns  : {report['known_patterns']}")
        print(f"  │  Co-occurrence   : {report['cooccurrence_pairs']} pairs")
        print(f"  │  Incubating      : {report['incubating_novel']} novel patterns")
        print(f"  │  Signatures      : {report['signatures_logged']} fingerprints")
        print(f"  │  Neural active   : {report['neural_active']}")
        if report["rising_threats"]:
            print(f"  │  RISING threats  : {report['rising_threats']}")
        print(f"  └─────────────────────────────────────────────────")

    def _top_confidence_patterns(self):
        sorted_kb = sorted(self.knowledge.items(),
                           key=lambda x: -x[1].get("confidence", 0))
        return [
            {"pattern": k, "confidence": v["confidence"],
             "sightings": v.get("sightings", 0)}
            for k, v in sorted_kb[:5]
        ]

    # ══════════════════════════════════════════════════════════════════════
    # UTILITIES + PERSISTENCE
    # ══════════════════════════════════════════════════════════════════════

    def _build_reasoning(self, finding_id, match_key, confidence,
                          co_boost, verdict, cve_refs, prediction):
        parts = []
        if match_key:
            parts.append(f"Matched pattern '{match_key}'")
        else:
            parts.append("No known pattern matched")
        if co_boost > 0:
            parts.append(f"co-occurrence boost +{co_boost}")
        parts.append(f"final confidence {confidence}")
        if cve_refs:
            parts.append(f"cross-referenced {len(cve_refs)} CVE(s)")
        if prediction:
            parts.append(f"predicting {prediction} also present")
        return " | ".join(parts)

    def _fingerprint_steps(self, steps):
        raw = json.dumps(sorted(steps), sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()

    def _pair_key(self, a, b):
        return "|".join(sorted([a.lower(), b.lower()]))

    def _today(self):
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _infer_scan_number(self):
        decisions = self.log.get("decisions", [])
        scans     = {d.get("scan") for d in decisions if "scan" in d}
        return len(scans) + 1

    def _log(self, message):
        self.log.setdefault("decisions", []).append({
            "scan"     : self.scan_number,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message"  : message
        })

    def _load(self, path, default):
        try:
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return deepcopy(default)

    def _save(self, path, data):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _save_all(self):
        self._save(KB_PATH,  self.knowledge)
        self._save(CO_PATH,  self.cooccurrence)
        self._save(INC_PATH, self.incubation)
        self._save(VEL_PATH, self.velocity)
        self._save(SIG_PATH, self.signatures)
        self._save(LOG_PATH, self.log)