from __future__ import annotations
import random
from datetime import datetime, timezone

ACOUSTIC_PATTERNS = [
    ("chainsaw_detected", "ECO-001", "CRITICAL", 9.5, "Chainsaw signature — active illegal logging"),
    ("gunshot_detected",  "ECO-006", "CRITICAL", 9.0, "Gunshot detected — suspected poaching"),
    ("heavy_vehicle",     "ECO-002", "HIGH",     7.8, "Heavy vehicle in protected zone"),
    ("fire_crackle",      "ECO-007", "HIGH",     7.5, "Fire signature — vegetation burning"),
    ("human_activity",    "ECO-008", "MEDIUM",   5.5, "Human activity in wildlife corridor"),
]


class AcousticScanner:
    def scan_node(self, node_id, lat, lng, region="Unknown"):
        rng      = random.Random(hash(node_id) % 10000)
        findings = []
        for i in range(rng.randint(0, 5)):
            roll = rng.random()
            pat  = (ACOUSTIC_PATTERNS[0] if roll < 0.05 else
                    ACOUSTIC_PATTERNS[1] if roll < 0.10 else
                    ACOUSTIC_PATTERNS[2] if roll < 0.20 else
                    ACOUSTIC_PATTERNS[3] if roll < 0.30 else
                    ACOUSTIC_PATTERNS[4])
            event_type, eco_code, severity, bio_score, desc = pat
            findings.append({
                "call_name" : event_type,
                "cwe_id"    : eco_code,
                "severity"  : severity,
                "cvss_score": bio_score,
                "file"      : f"{region}/{node_id}",
                "line"      : 0,
                "title"     : desc,
                "language"  : "acoustic",
                "snippet"   : f"Node {node_id} | {lat:.4f},{lng:.4f} | conf=0.91",
                "eco"       : {"node_id": node_id, "lat": lat, "lng": lng,
                               "region": region, "bio_score": bio_score, "eco_code": eco_code},
            })
        s = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": len(findings)}
        for f in findings:
            s[f["severity"].lower()] = s.get(f["severity"].lower(), 0) + 1
        print(f"[ACOUSTIC SCANNER] Node {node_id} @ {region}: {len(findings)} events")
        return {"language": "acoustic", "scanner": "Acoustic Scanner",
                "files": 1, "findings": findings, "summary": s,
                "scanned_at": datetime.now(timezone.utc).isoformat()}
