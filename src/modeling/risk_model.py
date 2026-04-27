"""
risk_model.py
Joins pathogen incidents with ecosystem health (NDVI) to compute
Bio-Threat Unit (BTU) risk scores.

Risk formula (v1):
  risk = w_cases * norm(case_count)
       + w_ndvi  * (1 - ndvi_mean)      # low vegetation = higher risk
       + w_tree  * (1 - norm(tree_cover_pct))
       + w_source * source_weight
"""
import pandas as pd
import numpy as np
from pathlib import Path

SOURCE_WEIGHTS = {"lab": 1.0, "community": 0.7, "environmental": 0.5}
WEIGHTS = {"cases": 0.40, "ndvi": 0.30, "tree": 0.15, "source": 0.15}

def _norm(series: pd.Series) -> pd.Series:
    mn, mx = series.min(), series.max()
    if mx == mn:
        return pd.Series(0.5, index=series.index)
    return (series - mn) / (mx - mn)

def compute_risk(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out["w_cases"]  = _norm(out["case_count"])  * WEIGHTS["cases"]
    out["w_ndvi"]   = (1 - out["ndvi_mean"].clip(0, 1)) * WEIGHTS["ndvi"]
    out["w_tree"]   = (1 - _norm(out.get("tree_cover_pct", pd.Series(0, index=out.index)))) * WEIGHTS["tree"]
    out["w_source"] = out["source_type"].map(SOURCE_WEIGHTS).fillna(0.5) * WEIGHTS["source"]
    out["risk_score"] = (out[["w_cases", "w_ndvi", "w_tree", "w_source"]].sum(axis=1)).round(4)
    out["risk_tier"]  = pd.cut(out["risk_score"],
                                bins=[0, 0.33, 0.66, 1.01],
                                labels=["LOW", "MEDIUM", "HIGH"])
    return out.drop(columns=["w_cases", "w_ndvi", "w_tree", "w_source"])

if __name__ == "__main__":
    from src.ingestion.lab_intake import ingest
    df = ingest(Path("data/synthetic/synthetic_outbreak.csv"))
    scored = compute_risk(df)
    print(scored[["pathogen_name", "region", "case_count", "ndvi_mean", "risk_score", "risk_tier"]].head(10))
    out_path = Path("data/synthetic/scored_outbreak.csv")
    scored.to_csv(out_path, index=False)
    print(f"\nSaved → {out_path}")
