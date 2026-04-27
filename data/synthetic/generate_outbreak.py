"""
generate_outbreak.py
Produces a synthetic East Africa biosecurity dataset for pipeline demos.
Pathogens, locations, and case counts are fictional.
"""
import numpy as np
import pandas as pd
from pathlib import Path

RNG = np.random.default_rng(42)

REGIONS = [
    ("Nairobi",    -1.286389,  36.817223),
    ("Mombasa",    -4.043477,  39.668206),
    ("Kisumu",     -0.091702,  34.767956),
    ("Kampala",     0.347596,  32.582520),
    ("Dar es Salaam", -6.792354, 39.208328),
    ("Lamu",       -2.269440,  40.902060),
    ("Garissa",    -0.453220,  39.646099),
]

PATHOGENS = ["Rift Valley Fever", "Crimean-Congo HF", "Mpox", "Leptospirosis", "Avian Influenza H5N1"]

n = 500
region_idx = RNG.integers(0, len(REGIONS), n)
pathogen_idx = RNG.integers(0, len(PATHOGENS), n)
dates = pd.date_range("2021-01-01", "2024-12-31", periods=n)

df = pd.DataFrame({
    "incident_id":    [f"INC-{i:05d}" for i in range(n)],
    "pathogen_name":  [PATHOGENS[i] for i in pathogen_idx],
    "detection_date": dates,
    "region":         [REGIONS[i][0] for i in region_idx],
    "location_lat":   [REGIONS[i][1] + RNG.uniform(-0.5, 0.5) for i in region_idx],
    "location_lon":   [REGIONS[i][2] + RNG.uniform(-0.5, 0.5) for i in region_idx],
    "case_count":     RNG.negative_binomial(3, 0.3, n),
    "source_type":    RNG.choice(["lab", "environmental", "community"], n, p=[0.5, 0.2, 0.3]),
    "ndvi_mean":      RNG.uniform(0.1, 0.7, n).round(3),
    "tree_cover_pct": RNG.uniform(0, 60, n).round(1),
    "risk_score":     RNG.uniform(0, 1, n).round(3),
})

out = Path(__file__).parent / "synthetic_outbreak.csv"
df.to_csv(out, index=False)
print(f"Saved {len(df)} rows → {out}")
