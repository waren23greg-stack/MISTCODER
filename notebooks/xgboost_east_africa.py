#!/usr/bin/env python3
"""
xgboost_east_africa.py

Train an XGBoost crop-yield model for East Africa using:
  - Sentinel-2 NDVI via GEE (--simulate fallback available)
  - TAHMO rainfall/temperature (--simulate fallback available)
  - Soil covariates via SoilGrids REST API (--simulate fallback available)

Usage:
  python notebooks/xgboost_east_africa.py --simulate --n-samples 300
  python notebooks/xgboost_east_africa.py            # real data
"""
import os
import time
import argparse
import logging
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, KFold, cross_val_score
from sklearn.metrics import r2_score, mean_squared_error, mean_absolute_error
import xgboost as xgb
import joblib
import requests

try:
    import ee
    GEE_AVAILABLE = True
except Exception:
    GEE_AVAILABLE = False

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

ROOT        = Path(__file__).parent.parent
ARTIFACTS   = ROOT / "artifacts"
ARTIFACTS.mkdir(parents=True, exist_ok=True)
MODEL_PATH  = ARTIFACTS / "xgb_east_africa_yield.joblib"
DATA_CSV    = ARTIFACTS / "dataset_east_africa.csv"
METRICS_CSV = ARTIFACTS / "training_metrics.csv"

EA_BBOX    = [29.5, -5.5, 41.9, 5.5]
START_DATE = "2022-01-01"
END_DATE   = "2024-12-31"


# ── CLI ───────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--simulate",   action="store_true",
                   help="Use synthetic data — no API keys required")
    p.add_argument("--n-samples",  type=int, default=300,
                   help="Synthetic sample count (default 300)")
    p.add_argument("--gee-project",
                   default=os.getenv("GOOGLE_CLOUD_PROJECT", ""),
                   help="GEE Cloud project ID")
    return p.parse_args()


# ── GEE init ──────────────────────────────────────────────────────────
def init_gee(project: str) -> bool:
    if not GEE_AVAILABLE:
        return False
    try:
        ee.Initialize(project=project if project else None)
        log.info("GEE initialised with project=%s", project or "default")
        return True
    except Exception as exc:
        log.warning("GEE init failed (%s). Remote NDVI unavailable.", exc)
        return False


# ── NDVI ──────────────────────────────────────────────────────────────
def get_monthly_ndvi(bbox, start_date, end_date, simulate=True):
    dates = pd.date_range(start=start_date, end=end_date, freq="ME")
    if simulate:
        # vary phase and amplitude by location so each bbox gives a unique signal
        cx = (bbox[0] + bbox[2]) / 2
        cy = (bbox[1] + bbox[3]) / 2
        phase = (cx * 0.3 + cy * 0.5) % (2 * np.pi)
        amp   = 0.25 + 0.15 * abs(np.sin(cy * 0.4))
        base  = 0.25 + 0.15 * abs(np.cos(cx * 0.3))
        vals  = (base
                 + amp * np.sin(np.linspace(phase, phase + 6 * np.pi, len(dates)))
                 + 0.05 * np.random.randn(len(dates))).clip(0, 1)
        return pd.DataFrame({"date": dates, "ndvi_median": vals})

    if not GEE_AVAILABLE:
        raise RuntimeError(
            "GEE not available — pass --simulate or install earthengine-api")

    geom = ee.Geometry.BBox(*bbox)
    col  = (ee.ImageCollection("COPERNICUS/S2_SR_HARMONIZED")
            .filterBounds(geom)
            .filterDate(start_date, end_date)
            .filter(ee.Filter.lt("CLOUDY_PIXEL_PERCENTAGE", 20))
            .map(lambda img: img.normalizedDifference(["B8", "B4"]).rename("NDVI")))

    rows = []
    for m in dates:
        m0  = m.replace(day=1).strftime("%Y-%m-%d")
        m1  = m.strftime("%Y-%m-%d")
        img = col.filterDate(m0, m1).median().select("NDVI")
        val = img.reduceRegion(
            ee.Reducer.median(), geom, scale=500, maxPixels=1e9
        ).get("NDVI").getInfo()
        rows.append({"date": m,
                     "ndvi_median": float(val) if val is not None else np.nan})
        time.sleep(0.15)

    df = pd.DataFrame(rows)
    df["ndvi_median"] = df["ndvi_median"].interpolate().clip(0, 1)
    return df


# ── Weather ───────────────────────────────────────────────────────────
def get_monthly_weather(bbox=None, start_date=START_DATE,
                        end_date=END_DATE, simulate=True):
    dates = pd.date_range(start=start_date, end=end_date, freq="ME")
    if simulate:
        cx = (bbox[0] + bbox[2]) / 2 if bbox else 35.0
        cy = (bbox[1] + bbox[3]) / 2 if bbox else 0.0
        rain_base = 60 + 40 * abs(np.cos(cy * 0.4))
        rain = (rain_base
                + 35 * np.sin(np.linspace(cx * 0.1, cx * 0.1 + 4 * np.pi, len(dates)))
                + 10 * np.random.randn(len(dates))).clip(0)
        temp = (18 + 5 * abs(np.sin(cy * 0.3))
                + 3 * np.sin(np.linspace(0, 2 * np.pi, len(dates)))
                + 0.5 * np.random.randn(len(dates)))
        return pd.DataFrame({"date": dates, "rain_mm": rain, "temp_c": temp})

    base = os.getenv("TAHMO_API_URL", "").rstrip("/")
    key  = os.getenv("TAHMO_API_KEY", "")
    if not base or not key:
        raise RuntimeError(
            "Set TAHMO_API_URL and TAHMO_API_KEY env vars, or use --simulate")

    headers = {"Authorization": f"Bearer {key}"}
    params  = {"start": start_date, "end": end_date}
    if bbox:
        params["bbox"] = ",".join(map(str, bbox))

    resp     = requests.get(f"{base}/stations", headers=headers,
                            params=params, timeout=30)
    resp.raise_for_status()
    stations = resp.json().get("stations", [])[:3]
    if not stations:
        raise RuntimeError("No TAHMO stations found in bbox")

    records = []
    for s in stations:
        sid = s.get("id") or s.get("station_id")
        r   = requests.get(f"{base}/stations/{sid}/observations",
                           headers=headers, params=params, timeout=30)
        r.raise_for_status()
        for obs in r.json().get("observations", []):
            ts = obs.get("timestamp") or obs.get("time") or obs.get("date")
            if not ts:
                continue
            records.append({
                "date":    pd.to_datetime(ts),
                "rain_mm": obs.get("rain_mm") or obs.get("precipitation") or 0,
                "temp_c":  obs.get("air_temperature") or obs.get("temp_c"),
            })

    df = (pd.DataFrame(records)
          .dropna(subset=["date"])
          .set_index("date")
          .sort_index())
    df["rain_mm"] = pd.to_numeric(df["rain_mm"], errors="coerce").fillna(0)
    df["temp_c"]  = pd.to_numeric(df["temp_c"],  errors="coerce").interpolate()
    return df.resample("ME").agg(
        {"rain_mm": "sum", "temp_c": "mean"}).reset_index()


# ── Soil ──────────────────────────────────────────────────────────────
def get_soil(lat, lon, simulate=True):
    if simulate:
        return {
            "soil_org_c":    float(np.clip(1.2 + 0.4 * np.random.randn(), 0.1, 5)),
            "soil_clay_pct": float(np.clip(25  + 6   * np.random.randn(), 5,  70)),
            "soil_sand_pct": float(np.clip(45  + 6   * np.random.randn(), 5,  85)),
            "soil_ph":       float(np.clip(6.2 + 0.4 * np.random.randn(), 4,   9)),
        }

    url  = (f"https://rest.isric.org/soilgrids/v2.0/properties/query"
            f"?lon={lon}&lat={lat}")
    resp = requests.get(url, timeout=20)
    resp.raise_for_status()
    layers = resp.json().get("properties", {}).get("layers", [])
    result = {"soil_org_c": 1.0, "soil_clay_pct": 25.0,
              "soil_sand_pct": 45.0, "soil_ph": 6.2}
    for layer in layers:
        name = layer.get("name", "")
        val  = None
        for d in layer.get("depths", []):
            v = d.get("values", {}).get("mean")
            if v is not None:
                val = v
                break
        if val is None:
            continue
        if name == "soc":
            result["soil_org_c"]    = float(val) / 10
        elif name == "clay":
            result["soil_clay_pct"] = float(val) / 10
        elif name == "sand":
            result["soil_sand_pct"] = float(val) / 10
        elif name == "phh2o":
            result["soil_ph"]       = float(val) / 10
    return result


# ── Feature engineering ───────────────────────────────────────────────
def build_features(bbox=EA_BBOX, start_date=START_DATE,
                   end_date=END_DATE, simulate=True):
    ndvi_df    = get_monthly_ndvi(bbox, start_date, end_date, simulate)
    weather_df = get_monthly_weather(bbox=bbox, start_date=start_date, end_date=end_date, simulate=simulate)
    lon = (bbox[0] + bbox[2]) / 2
    lat = (bbox[1] + bbox[3]) / 2
    soil = get_soil(lat, lon, simulate)

    n = ndvi_df["ndvi_median"]
    r = weather_df["rain_mm"]
    t = weather_df["temp_c"]

    feats = {
        "ndvi_mean":           float(n.mean()),
        "ndvi_std":            float(n.std()),
        "ndvi_max":            float(n.max()),
        "ndvi_min":            float(n.min()),
        "ndvi_amp":            float(n.max() - n.min()),
        "ndvi_growing_season": float(n[n > 0.4].mean())
                               if (n > 0.4).any() else 0.0,
        "rain_total":          float(r.sum()),
        "rain_mean":           float(r.mean()),
        "rain_cv":             float(r.std() / (r.mean() + 1e-6)),
        "temp_mean":           float(t.mean()),
        "temp_range":          float(t.max() - t.min()),
        "lat":                 lat,
        "lon":                 lon,
    }
    feats.update(soil)

    if simulate:
        noise = np.random.randn() * 0.2
        y = (
            1.0
            + 4.0  * feats["ndvi_mean"]
            + 1.5  * feats["ndvi_growing_season"]
            + 0.003 * feats["rain_total"]
            - 0.05 * feats["rain_cv"]
            + 0.15 * feats["soil_org_c"]
            - 0.01 * abs(lat)
            + noise
        )
        feats["yield_t_ha"] = float(np.clip(y, 0.1, 10))
        return pd.DataFrame([feats])

    raise NotImplementedError(
        "Real yield data not wired up. "
        "Provide a ground-truth CSV or use --simulate.")


# ── Dataset ───────────────────────────────────────────────────────────
def create_dataset(n_samples=300, simulate=True):
    rng  = np.random.default_rng(42)
    lons = rng.uniform(EA_BBOX[0], EA_BBOX[2], n_samples)
    lats = rng.uniform(EA_BBOX[1], EA_BBOX[3], n_samples)
    rows = []
    for i, (lo, la) in enumerate(zip(lons, lats)):
        bbox = [lo - 0.5, la - 0.5, lo + 0.5, la + 0.5]
        df   = build_features(bbox=bbox, simulate=simulate)
        rows.append(df.iloc[0])
        if (i + 1) % 50 == 0:
            log.info("  built %d / %d rows", i + 1, n_samples)
    return pd.DataFrame(rows).reset_index(drop=True)


# ── Training ──────────────────────────────────────────────────────────
def train(data: pd.DataFrame) -> dict:
    TARGET   = "yield_t_ha"
    FEATURES = [c for c in data.columns if c != TARGET]
    X, y     = data[FEATURES], data[TARGET]

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42)

    model = xgb.XGBRegressor(
        n_estimators=200,
        learning_rate=0.04,
        max_depth=5,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        reg_alpha=0.1,
        reg_lambda=1.0,
        random_state=42,
        tree_method="hist",
    )

    model.fit(X_tr, y_tr, eval_set=[(X_te, y_te)], verbose=False)

    y_pred = model.predict(X_te)
    r2     = float(r2_score(y_te, y_pred))
    rmse   = float(np.sqrt(mean_squared_error(y_te, y_pred)))
    mae    = float(mean_absolute_error(y_te, y_pred))

    cv_scores = cross_val_score(
        xgb.XGBRegressor(
            n_estimators=200,
            learning_rate=0.04, max_depth=5,
            subsample=0.8, colsample_bytree=0.8,
            random_state=42, tree_method="hist",
        ),
        X, y,
        cv=KFold(5, shuffle=True, random_state=42),
        scoring="r2",
    )
    cv_mean = float(cv_scores.mean())
    cv_std  = float(cv_scores.std())

    log.info("Hold-out  R2=%.3f  RMSE=%.3f  MAE=%.3f", r2, rmse, mae)
    log.info("5-fold CV R2=%.3f +/- %.3f", cv_mean, cv_std)

    imp = pd.Series(model.feature_importances_, index=FEATURES)
    log.info("Top-5 features:\n%s", imp.nlargest(5).to_string())

    joblib.dump(model, MODEL_PATH)
    log.info("Model saved -> %s", MODEL_PATH)

    return {
        "r2":         r2,
        "rmse":       rmse,
        "mae":        mae,
        "cv_r2_mean": cv_mean,
        "cv_r2_std":  cv_std,
        "best_iter":  200,
        "model_path": str(MODEL_PATH),
    }


# ── Main ──────────────────────────────────────────────────────────────
def main():
    args     = parse_args()
    simulate = args.simulate

    if not simulate and args.gee_project:
        init_gee(args.gee_project)

    log.info("Building dataset  simulate=%s  n_samples=%d",
             simulate, args.n_samples)
    data = create_dataset(n_samples=args.n_samples, simulate=simulate)
    data.to_csv(DATA_CSV, index=False)
    log.info("Dataset saved -> %s  shape=%s", DATA_CSV, data.shape)

    metrics = train(data)
    pd.DataFrame([metrics]).to_csv(METRICS_CSV, index=False)
    log.info("Metrics saved -> %s", METRICS_CSV)

    print("\n── Results ───────────────────────────────")
    print(f"  Hold-out R2   : {metrics['r2']:.4f}")
    print(f"  Hold-out RMSE : {metrics['rmse']:.4f}")
    print(f"  Hold-out MAE  : {metrics['mae']:.4f}")
    print(f"  CV R2 (5-fold): {metrics['cv_r2_mean']:.4f} +/- {metrics['cv_r2_std']:.4f}")
    print(f"  Best iteration: {metrics['best_iter']}")
    print(f"  Model         : {metrics['model_path']}")
    print("──────────────────────────────────────────\n")


if __name__ == "__main__":
    main()
