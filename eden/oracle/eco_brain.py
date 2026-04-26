from __future__ import annotations
import json
import hashlib
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

SANDBOX = Path(__file__).resolve().parent.parent.parent / "sandbox"
ECO_KB  = SANDBOX / "eco_knowledge.json"
ECO_LOG = SANDBOX / "eco_brain_log.json"
ECO_CO  = SANDBOX / "eco_cooccurrence.json"
ECO_VEL = SANDBOX / "eco_velocity.json"

MAX_CONF   = 0.99
MIN_CONF   = 0.50

ECO_SEED = {
    "deforestation_event": {
        "impact_refs": ["IUCN-REDLIST-2023", "IPBES-2019"],
        "confidence": 0.95, "verdict": "VERIFIED_IMPACT", "sightings": 1,
        "first_seen": "2026-01-01", "last_seen": "2026-01-01",
        "eco_codes": ["ECO-001", "ECO-007"], "carbon_factor": 250,
        "description": "Active deforestation — canopy loss + carbon release",
        "species_alert": ["Forest elephants", "Colobus monkey"],
    },
    "illegal_clearing": {
        "impact_refs": ["CITES-2022", "CBD-COP15"],
        "confidence": 0.91, "verdict": "VERIFIED_IMPACT", "sightings": 1,
        "first_seen": "2026-01-01", "last_seen": "2026-01-01",
        "eco_codes": ["ECO-006", "ECO-001"], "carbon_factor": 220,
        "description": "Unauthorised land clearing in protected zone",
        "species_alert": ["All canopy species"],
    },
    "chainsaw_detected": {
        "impact_refs": ["REDD-PLUS-2023"],
        "confidence": 0.93, "verdict": "VERIFIED_IMPACT", "sightings": 1,
        "first_seen": "2026-01-01", "last_seen": "2026-01-01",
        "eco_codes": ["ECO-001", "ECO-006"], "carbon_factor": 180,
        "description": "Active chainsaw — imminent tree felling",
        "species_alert": ["Nesting birds", "Tree-dwelling primates"],
    },
    "habitat_fragmentation": {
        "impact_refs": ["IPBES-2019", "WWF-LPI-2022"],
        "confidence": 0.87, "verdict": "VERIFIED_IMPACT", "sightings": 1,
        "first_seen": "2026-01-01", "last_seen": "2026-01-01",
        "eco_codes": ["ECO-002", "ECO-008"], "carbon_factor": 80,
        "description": "Wildlife corridor breach — genetic isolation risk",
        "species_alert": ["Large mammals", "Migratory birds"],
    },
    "vegetation_stress": {
        "impact_refs": ["NASA-MODIS-2023"],
        "confidence": 0.82, "verdict": "VERIFIED_IMPACT", "sightings": 1,
        "first_seen": "2026-01-01", "last_seen": "2026-01-01",
        "eco_codes": ["ECO-005", "ECO-004"], "carbon_factor": 40,
        "description": "Sustained NDVI decline — drought or overgrazing",
        "species_alert": ["Grassland grazers"],
    },
    "gunshot_detected": {
        "impact_refs": ["CITES-2022"],
        "confidence": 0.90, "verdict": "VERIFIED_IMPACT", "sightings": 1,
        "first_seen": "2026-01-01", "last_seen": "2026-01-01",
        "eco_codes": ["ECO-006"], "carbon_factor": 0,
        "description": "Gunshot — suspected poaching event",
        "species_alert": ["Elephant", "Rhino", "Lion"],
    },
    "fire_crackle": {
        "impact_refs": ["FIRMS-NASA-2023"],
        "confidence": 0.88, "verdict": "VERIFIED_IMPACT", "sightings": 1,
        "first_seen": "2026-01-01", "last_seen": "2026-01-01",
        "eco_codes": ["ECO-007", "ECO-001"], "carbon_factor": 150,
        "description": "Active vegetation fire — carbon emission event",
        "species_alert": ["Ground-nesting species", "Small mammals"],
    },
}


class EcoBrain:
    def __init__(self, verbose=True):
        self.verbose      = verbose
        SANDBOX.mkdir(exist_ok=True)
        self.knowledge    = self._load(ECO_KB,  ECO_SEED)
        self.cooccurrence = self._load(ECO_CO,  {})
        self.velocity     = self._load(ECO_VEL, {})
        self.log          = self._load(ECO_LOG, {"decisions": []})
        self.scan_number  = len(self.log.get("decisions", [])) // 10 + 1
        self._log(f"EcoBrain online — scan #{self.scan_number} — {len(self.knowledge)} patterns")

    def evaluate(self, event_id, steps, bio_score, eco_context=None):
        eco_context     = eco_context or {}
        match_key, match_data = self._match_knowledge(steps)
        co_boost        = self._cooccurrence_boost(steps)
        base_conf       = match_data["confidence"] if match_data else 0.70
        final_conf      = min(MAX_CONF, base_conf + co_boost)

        if match_data:
            verdict     = match_data["verdict"]
            impact_refs = match_data["impact_refs"]
            carbon_est  = round(
                eco_context.get("area_ha", 10) *
                match_data.get("carbon_factor", 100) *
                abs(eco_context.get("ndvi_delta", 0.2)) / 0.35, 1)
            species     = match_data.get("species_alert", [])
        else:
            verdict, impact_refs, carbon_est, species = "EMERGING_THREAT", [], 0, []

        if final_conf < MIN_CONF:
            verdict = "UNDER_OBSERVATION"

        signature  = self._build_signature(event_id, steps, bio_score)
        prediction = self._predict_associated(steps)
        reasoning  = self._build_reasoning(event_id, match_key, final_conf,
                                           co_boost, verdict, impact_refs, carbon_est)
        self._update_knowledge(match_key, steps, final_conf)
        self._update_cooccurrence(steps)
        self._update_velocity(steps)
        self._save_all()

        result = {"confidence": round(final_conf, 4), "verdict": verdict,
                  "impact_refs": impact_refs, "carbon_tco2": carbon_est,
                  "species_risk": species, "prediction": prediction,
                  "reasoning": reasoning, "signature": signature[:16]}

        if self.verbose:
            self._print_evaluation(event_id, result)
        return result

    def end_scan(self):
        self.scan_number += 1
        self._save_all()
        print()
        print("  ┌─ ECO BRAIN SCAN SUMMARY ────────────────────────────")
        print(f"  │  Scan number    : #{self.scan_number}")
        print(f"  │  Known patterns : {len(self.knowledge)}")
        print(f"  │  Co-occurrences : {len(self.cooccurrence)} stressor pairs")
        print("  └─────────────────────────────────────────────────────")

    def _match_knowledge(self, steps):
        best_key, best_data, best_score = None, None, 0
        for step in steps:
            sl = step.lower().replace(" ", "_").replace("-", "_")
            for key, data in self.knowledge.items():
                if key in sl or sl in key:
                    s = len(key)
                    if s > best_score:
                        best_score, best_key, best_data = s, key, data
        return best_key, best_data

    def _cooccurrence_boost(self, steps):
        boost, pairs = 0.0, 0
        for i, a in enumerate(steps):
            for b in steps[i+1:]:
                key = "|".join(sorted([a.lower(), b.lower()]))
                if key in self.cooccurrence:
                    boost += min(0.15, self.cooccurrence[key].get("count", 0) * 0.05)
                    pairs += 1
        return round(min(0.20, boost / pairs if pairs else boost), 4)

    def _update_cooccurrence(self, steps):
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        for i, a in enumerate(steps):
            for b in steps[i+1:]:
                key = "|".join(sorted([a.lower(), b.lower()]))
                if key not in self.cooccurrence:
                    self.cooccurrence[key] = {"count": 0, "first_seen": today}
                self.cooccurrence[key]["count"]    += 1
                self.cooccurrence[key]["last_seen"]  = today

    def _update_velocity(self, steps):
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        for s in steps:
            if s not in self.velocity:
                self.velocity[s] = {"appearances": [], "trend": "STABLE"}
            self.velocity[s]["appearances"].append(self.scan_number)
            self.velocity[s]["last_seen"] = today

    def _predict_associated(self, steps):
        preds = {}
        for step in steps:
            sl = step.lower()
            for key in self.cooccurrence:
                parts = key.split("|")
                if len(parts) == 2:
                    other = parts[1] if sl in parts[0] else (parts[0] if sl in parts[1] else None)
                    if other and other not in steps:
                        preds[other] = preds.get(other, 0) + self.cooccurrence[key].get("count", 0)
        return [p[0] for p in sorted(preds.items(), key=lambda x: -x[1])[:3]]

    def _build_signature(self, event_id, steps, bio_score):
        eco_codes = sorted([s for s in steps if s.startswith("ECO")])
        calls     = sorted([s for s in steps if not s.startswith("ECO")])
        band      = ("CRITICAL" if bio_score >= 8.0 else "HIGH" if bio_score >= 6.0
                     else "MEDIUM" if bio_score >= 4.0 else "LOW")
        raw = json.dumps({"eco": eco_codes, "calls": calls, "band": band}, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()

    def _update_knowledge(self, match_key, steps, confidence):
        if not match_key or match_key not in self.knowledge:
            return
        entry = self.knowledge[match_key]
        entry["sightings"]  = entry.get("sightings", 0) + 1
        entry["last_seen"]  = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        entry["confidence"] = min(MAX_CONF,
                                  round(entry["confidence"] +
                                        (MAX_CONF - entry["confidence"]) * 0.03, 4))

    def _build_reasoning(self, event_id, match_key, conf, co_boost,
                          verdict, impact_refs, carbon):
        parts = [f"Matched eco-pattern '{match_key}'" if match_key
                 else "Novel ecological signature"]
        if co_boost > 0:
            parts.append(f"stressor co-occurrence +{co_boost}")
        parts.append(f"BioImpact confidence {conf}")
        if impact_refs:
            parts.append(f"refs: {', '.join(impact_refs[:2])}")
        if carbon > 0:
            parts.append(f"~{carbon} tCO2 at risk")
        return " | ".join(parts)

    def _print_evaluation(self, event_id, result):
        icons = {"VERIFIED_IMPACT": "✓", "EMERGING_THREAT": "?", "UNDER_OBSERVATION": "~"}
        icon  = icons.get(result["verdict"], ".")
        print(f"[ECO BRAIN] {icon} {event_id}")
        print(f"  Confidence  : {result['confidence']} | Verdict: {result['verdict']}")
        if result["impact_refs"]:
            print(f"  Impact refs : {', '.join(result['impact_refs'])}")
        if result["carbon_tco2"] > 0:
            print(f"  Carbon risk : ~{result['carbon_tco2']} tCO2")
        if result["species_risk"]:
            print(f"  Species     : {', '.join(result['species_risk'][:2])}")
        print(f"  Signature   : {result['signature']}")
        print()

    def _log(self, message):
        self.log.setdefault("decisions", []).append({
            "scan": self.scan_number,
            "ts"  : datetime.now(timezone.utc).isoformat(),
            "msg" : message,
        })

    def _load(self, path, default):
        try:
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
        return deepcopy(default)

    def _save(self, path, data):
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _save_all(self):
        self._save(ECO_KB,  self.knowledge)
        self._save(ECO_CO,  self.cooccurrence)
        self._save(ECO_VEL, self.velocity)
        self._save(ECO_LOG, self.log)
