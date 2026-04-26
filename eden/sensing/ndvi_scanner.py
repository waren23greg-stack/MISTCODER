from __future__ import annotations
import random
from datetime import datetime, timezone

ECO_PATTERNS = [
    (-0.35, "deforestation_event",   "ECO-001", "CRITICAL", 9.2, "Rapid NDVI collapse — active deforestation detected"),
    (-0.25, "illegal_clearing",      "ECO-006", "CRITICAL", 8.7, "Sudden canopy loss — illegal clearing"),
    (-0.20, "habitat_fragmentation", "ECO-002", "HIGH",     7.5, "Vegetation corridor breach"),
    (-0.15, "vegetation_stress",     "ECO-005", "HIGH",     6.8, "Sustained NDVI decline"),
    (-0.10, "soil_degradation",      "ECO-004", "MEDIUM",   5.5, "Topsoil exposure detected"),
    (-0.05, "edge_effect",           "ECO-008", "MEDIUM",   4.2, "Forest edge degradation"),
    ( 0.10, "invasive_expansion",    "ECO-003", "HIGH",     7.1, "Invasive species encroachment"),
]

SPECIES_REGISTRY = {
    "Mau Forest"        : ["Eastern black-and-white colobus", "African elephant", "Leopard"],
    "Rift Valley"       : ["Plains zebra", "Maasai giraffe", "Cheetah"],
    "Nairobi Eastlands" : ["Sykes monkey", "African civet"],
    "Default"           : ["Unknown endemic species"],
}

CARBON_STOCK = {"tropical_forest": 250, "woodland": 120, "grassland": 40, "wetland": 180}


class NDVIScanner:
    def __init__(self):
        self.findings = []

    def scan_region(self, lat, lng, region_name="Unknown",
                    biome="tropical_forest", radius_km=10.0):
        print(f"[NDVI SCANNER] Scanning {region_name} ({lat:.3f},{lng:.3f}) r={radius_km}km")
        pixels        = self._synthetic_ndvi(lat, lng, radius_km)
        self.findings = []
        for px in pixels:
            f = self._analyse_pixel(px, region_name, biome)
            if f:
                self.findings.append(f)
        s = self._summarise()
        print(f"[NDVI SCANNER] {len(pixels)} pixels -> {len(self.findings)} threats | "
              f"CRITICAL:{s['critical']} HIGH:{s['high']} MEDIUM:{s['medium']}")
        return {"language": "ndvi", "scanner": "NDVI Scanner",
                "region": region_name, "lat": lat, "lng": lng,
                "files": len(pixels), "findings": self.findings, "summary": s,
                "scanned_at": datetime.now(timezone.utc).isoformat()}

    def scan_regions(self, regions):
        all_f, total = [], 0
        for r in regions:
            res = self.scan_region(**r)
            all_f.extend(res["findings"])
            total += res["files"]
        s = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        for f in all_f:
            sev = f.get("severity", "LOW").lower()
            s[sev]     = s.get(sev, 0) + 1
            s["total"] += 1
        return {"language": "ndvi", "scanner": "NDVI Scanner",
                "files": total, "findings": all_f, "summary": s}

    def _synthetic_ndvi(self, lat, lng, radius_km):
        rng = random.Random(int(abs(lat * 1000) + abs(lng * 1000)))
        pixels, n = [], max(8, int(radius_km * 3))
        for i in range(n):
            ndvi_t1 = rng.uniform(0.55, 0.82)
            if rng.random() < 0.30:
                r2    = rng.random()
                delta = (rng.uniform(-0.50, -0.35) if r2 < 0.10 else
                         rng.uniform(-0.30, -0.20) if r2 < 0.30 else
                         rng.uniform(-0.18, -0.08))
            else:
                delta = rng.uniform(-0.04, 0.04)
            pixels.append({
                "pixel_id" : f"PX-{i+1:04d}",
                "lat"      : round(lat + rng.uniform(-radius_km/111, radius_km/111), 6),
                "lng"      : round(lng + rng.uniform(-radius_km/111, radius_km/111), 6),
                "ndvi_t1"  : round(ndvi_t1, 4),
                "ndvi_t2"  : round(max(0, ndvi_t1 + delta), 4),
                "ndvi_delta": round(delta, 4),
                "area_ha"  : round(rng.uniform(5, 200), 1),
            })
        return pixels

    def _analyse_pixel(self, px, region_name, biome):
        delta   = px["ndvi_delta"]
        matched = None
        for threshold, event_type, eco_code, severity, bio_score, desc in ECO_PATTERNS:
            if (threshold < 0 and delta <= threshold) or (threshold > 0 and delta >= threshold):
                matched = (event_type, eco_code, severity, bio_score, desc)
                break
        if not matched:
            return None
        event_type, eco_code, severity, bio_score, desc = matched
        area_ha = px["area_ha"]
        carbon  = round(area_ha * CARBON_STOCK.get(biome, 120) * abs(delta) / 0.35, 1)
        species = SPECIES_REGISTRY.get(region_name, SPECIES_REGISTRY["Default"])
        return {
            "call_name" : event_type,
            "cwe_id"    : eco_code,
            "severity"  : severity,
            "cvss_score": bio_score,
            "file"      : f"{region_name}/{px['pixel_id']}",
            "line"      : 0,
            "title"     : desc,
            "language"  : "ndvi",
            "snippet"   : f"NDVI {px['ndvi_t1']}→{px['ndvi_t2']} delta={delta} area={area_ha}ha",
            "eco"       : {
                "pixel_id"   : px["pixel_id"],
                "lat"        : px["lat"],
                "lng"        : px["lng"],
                "region"     : region_name,
                "biome"      : biome,
                "ndvi_before": px["ndvi_t1"],
                "ndvi_after" : px["ndvi_t2"],
                "ndvi_delta" : delta,
                "area_ha"    : area_ha,
                "carbon_tco2": carbon,
                "species_risk": species,
                "eco_code"   : eco_code,
                "bio_score"  : bio_score,
            },
        }

    def _summarise(self):
        s = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        for f in self.findings:
            sev = f.get("severity", "LOW").lower()
            s[sev]     = s.get(sev, 0) + 1
            s["total"] += 1
        return s
