#!/usr/bin/env python3
"""
xgboost_east_africa.py

Train an XGBoost crop-yield model for East Africa using:
- Sentinel-2 NDVI via GEE (SIMULATE fallback)
- TAHMO rainfall/temperature (SIMULATE fallback)
- Soil covariates via SoilGrids (ISRIC) as a working fallback for iSDA

Usage:
  # quick test with synthetic data
  python notebooks/xgboost_east_africa.py --simulate

  # real run (requires GEE auth and API keys for TAHMO/iSDA if used)
  python notebooks/xgboost_east_africa.py
"""
import os
import time
import argparse
from pathlib import Path
import logging
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import r2_score, mean_squared_error
import xgboost as xgb
import joblib
import requests

# Optional geospatial libs (only required when using real GEE)
try:
    import ee
    GEE_AVAILABLE = True
except Exception:
    GEE_AVAILABLE = False

ROOT = Path.cwd()
ARTIFACTS_DIR = ROOT / "artifacts"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
MODEL_PATH = ARTIFACTS_DIR / "xgb_east_africa_yield.joblib"
DATA_CSV = ARTIFACTS_DIR / "dataset_east_africa.csv"

# East Africa bbox (min_lon, min_lat, max_lon, max_lat)
EA_BBOX = [29.5, -5.5, 41.9, 5.5]
START_DATE = "2022-01-01"
END_DATE = "2024-12-31"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--simulate", action="store_true", help="Use synthetic data (no API keys required)")
    p.add_argument("--n-samples", type=int, default=300, help="Number of synthetic samples to generate")
    return p.parse_args()


def get_monthly_ndvi_timeseries_gee(bbox, start_date, end_date, simulate=True):
    """
    Return monthly median NDVI time series for the bbox centroid.
    If simulate=True returns synthetic NDVI series.
    """
    # Use 'ME' monthly end frequency to avoid pandas FutureWarning
    if simulate:
        dates = pd.date_range(start=start_date, end=end_date, freq="ME")
        df = pd.DataFrame({
            "date": dates,
            "ndvi_median": 0.2 + 0.4 * np.sin(np.linspace(0, 6 * np.pi, len(dates))) + 0.05 * np.random.randn(len(dates))
        })
        return df

    if not GEE_AVAILABLE:
        raise RuntimeError("GEE not available. Install earthengine-api and set simulate=True or install dependencies.")

    geom = ee.Geometry.BBox(*bbox)
    s2 = (ee.ImageCollection("COPERNICUS/S2_SR")
          .filterBounds(geom)
          .filterDate(start_date, end_date)
          .map(lambda img: img.normalizedDifference(["B8", "B4"]).rename("NDVI")))

    start = pd.to_datetime(start_date)
    end = pd.to_datetime(end_date)
    months = pd.date_range(start=start, end=end, freq="ME")
    rows = []
    for m in months:
        m_start = ee.Date(m.replace(day=1).strftime("%Y-%m-%d"))
        m_end = ee.Date((m + pd.offsets.MonthEnd(0)).strftime("%Y-%m-%d"))
        img = s2.filterDate(m_start, m_end).median().select("NDVI")
        stat = img.reduceRegion(reducer=ee.Reducer.median(), geometry=geom, scale=1000, maxPixels=1e9)
        ndvi_val = stat.get("NDVI").getInfo() if stat.get("NDVI") else None
        rows.append({"date": m.to_pydatetime(), "ndvi_median": ndvi_val})
        time.sleep(0.15)
    df = pd.DataFrame(rows)
    df["ndvi_median"] = df["ndvi_median"].astype(float)
    return df


def fetch_tahmo_station_timeseries(station_id=None, bbox=None, start_date=START_DATE, end_date=END_DATE, simulate=True):
    """
    Returns monthly rainfall (mm) and temperature (C) aggregates as pandas DataFrame.
    - If simulate=True returns synthetic series.
    - If simulate=False, expects env vars:
        TAHMO_API_URL (base URL) and TAHMO_API_KEY (token)
      The function will try to fetch observations for a station or bbox and aggregate monthly.
    Note: adapt parsing to the exact TAHMO JSON schema if needed.
    """
    if simulate:
        dates = pd.date_range(start=start_date, end=end_date, freq="ME")
        df = pd.DataFrame({
            "date": dates,
            "rain_mm": 80 + 40 * np.sin(np.linspace(0, 4 * np.pi, len(dates))) + 10 * np.random.randn(len(dates)),
            "temp_c": 20 + 3 * np.sin(np.linspace(0, 2 * np.pi, len(dates))) + 0.5 * np.random.randn(len(dates))
        })
        return df

    base = os.getenv("TAHMO_API_URL")
    key = os.getenv("TAHMO_API_KEY")
    if not base or not key:
        raise RuntimeError("TAHMO_API_URL or TAHMO_API_KEY not set. Use --simulate or set env vars.")

    headers = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
    params = {"start": start_date, "end": end_date}

    # Prefer station_id if provided; otherwise query stations in bbox and pick nearest
    if station_id:
        url = f"{base.rstrip('/')}/stations/{station_id}/observations"
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        payload = resp.json()
        records = []
        for obs in payload.get("observations", []):
            ts = obs.get("timestamp") or obs.get("time") or obs.get("date")
            if not ts:
                continue
            dt = pd.to_datetime(ts)
            rain = obs.get("rain_mm") if obs.get("rain_mm") is not None else obs.get("precipitation")
            temp = obs.get("air_temperature") if obs.get("air_temperature") is not None else obs.get("temp_c")
            records.append({"date": dt, "rain_mm": rain, "temp_c": temp})
        if not records:
            raise RuntimeError("No observations returned from TAHMO for station.")
        df = pd.DataFrame(records)
    else:
        url = f"{base.rstrip('/')}/stations"
        if bbox:
            params.update({"bbox": ",".join(map(str, bbox))})
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        stations = resp.json().get("stations", [])
        if not stations:
            raise RuntimeError("No stations found in bbox.")
        stations = stations[:3]
        all_records = []
        for s in stations:
            sid = s.get("id") or s.get("station_id")
            if not sid:
                continue
            url_s = f"{base.rstrip('/')}/stations/{sid}/observations"
            r = requests.get(url_s, headers=headers, params=params, timeout=30)
            r.raise_for_status()
            payload = r.json()
            for obs in payload.get("observations", []):
                ts = obs.get("timestamp") or obs.get("time") or obs.get("date")
                if not ts:
                    continue
                dt = pd.to_datetime(ts)
                rain = obs.get("rain_mm") if obs.get("rain_mm") is not None else obs.get("precipitation")
                temp = obs.get("air_temperature") if obs.get("air_temperature") is not None else obs.get("temp_c")
                all_records.append({"date": dt, "rain_mm": rain, "temp_c": temp})
        if not all_records:
            raise RuntimeError("No observations returned from TAHMO stations in bbox.")
        df = pd.DataFrame(all_records)

    # Normalize and aggregate to monthly
    df = df.dropna(subset=["date"])
    df["date"] = pd.to_datetime(df["date"])
    df = df.set_index("date").sort_index()
    df["rain_mm"] = pd.to_numeric(df["rain_mm"], errors="coerce").fillna(0.0)
    df["temp_c"] = pd.to_numeric(df["temp_c"], errors="coerce").interpolate().fillna(method="bfill").fillna(method="ffill")
    monthly = df.resample("M").agg({"rain_mm": "sum", "temp_c": "mean"}).reset_index()
    return monthly


def fetch_isda_soil(lat, lon, simulate=True):
    """
    If simulate=True returns synthetic soil features.
    If simulate=False, this function queries ISRIC SoilGrids as a practical fallback.
    Replace with iSDA API/raster access when available.
    """
    if simulate:
        return {
            "soil_org_c": float(1.2 + 0.3 * np.random.randn()),
            "soil_clay_pct": float(25 + 5 * np.random.randn()),
            "soil_sand_pct": float(45 + 5 * np.random.randn()),
            "soil_ph": float(6.2 + 0.3 * np.random.randn())
        }

    url = f"https://rest.soilgrids.org/query?lon={lon}&lat={lat}"
    r = requests.get(url, timeout=20)
    r.raise_for_status()
    payload = r.json()
    props = payload.get("properties", {})

    def safe_get(prop, layer="0-5cm"):
        v = props.get(prop, {})
        if not v:
            return None
        if isinstance(v, dict) and "M" in v:
            return v["M"]
        if isinstance(v, dict) and "values" in v and isinstance(v["values"], dict):
            return v["values"].get(layer)
        return None

    soil_org_c = safe_get("soc") or safe_get("soc_0-5cm") or 1.0
    clay = safe_get("clay") or 25.0
    sand = safe_get("sand") or 45.0
    ph = safe_get("phh2o") or 6.2

    return {
        "soil_org_c": float(soil_org_c),
        "soil_clay_pct": float(clay),
        "soil_sand_pct": float(sand),
        "soil_ph": float(ph)
    }


def build_feature_table(bbox=EA_BBOX, start_date=START_DATE, end_date=END_DATE, simulate=True):
    """
    Build a single-row feature table for a bbox:
    - NDVI summaries (mean, std, max, min, amplitude)
    - Rainfall aggregates and mean temperature
    - Soil covariates (soil_org_c, clay, sand, ph)
    - Synthetic target yield_t_ha when simulate=True
    """
    ndvi_df = get_monthly_ndvi_timeseries_gee(bbox, start_date, end_date, simulate=simulate)
    tahmo_df = fetch_tahmo_station_timeseries(bbox=bbox, start_date=start_date, end_date=end_date, simulate=simulate)

    feats = {}
    feats["ndvi_mean"] = float(ndvi_df["ndvi_median"].mean())
    feats["ndvi_std"] = float(ndvi_df["ndvi_median"].std())
    feats["ndvi_max"] = float(ndvi_df["ndvi_median"].max())
    feats["ndvi_min"] = float(ndvi_df["ndvi_median"].min())
    feats["ndvi_amp"] = feats["ndvi_max"] - feats["ndvi_min"]

    feats["rain_total"] = float(tahmo_df["rain_mm"].sum())
    feats["rain_mean"] = float(tahmo_df["rain_mm"].mean())
    feats["temp_mean"] = float(tahmo_df["temp_c"].mean())

    lon = (bbox[0] + bbox[2]) / 2.0
    lat = (bbox[1] + bbox[3]) / 2.0
    soil = fetch_isda_soil(lat, lon, simulate=simulate)
    feats.update(soil)

    if simulate:
        # synthetic target correlated with NDVI, rainfall, and soil organic carbon
        y = 1.5 + 3.0 * feats["ndvi_mean"] + 0.002 * feats["rain_total"] + 0.1 * feats["soil_org_c"] + np.random.randn() * 0.3
        feats["yield_t_ha"] = float(y)
        return pd.DataFrame([feats])

    raise NotImplementedError("Real yield ingestion not implemented. Provide ground truth yield CSV or set simulate=True.")


def create_dataset(n_samples=300, simulate=True):
    """
    Create a dataset by jittering bbox centroids across the East Africa region.
    Returns a DataFrame with n_samples rows.
    """
    rows = []
    for i in range(n_samples):
        dx = np.random.uniform(-1.0, 1.0)
        dy = np.random.uniform(-1.0, 1.0)
        bbox = [EA_BBOX[0] + dx, EA_BBOX[1] + dy, EA_BBOX[2] + dx, EA_BBOX[3] + dy]
        df = build_feature_table(bbox=bbox, simulate=simulate)
        rows.append(df.iloc[0])
    dataset = pd.DataFrame(rows)
    return dataset


def train_xgboost(data):
    """
    Train an XGBoost regressor with a fallback to xgb.train if the sklearn wrapper
    does not accept early_stopping_rounds on this environment.
    Returns metrics dict with r2, rmse, model_path.
    """
    TARGET = "yield_t_ha"
    FEATURES = [c for c in data.columns if c != TARGET]
    X = data[FEATURES]
    y = data[TARGET]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = xgb.XGBRegressor(
        n_estimators=500,
        learning_rate=0.05,
        max_depth=6,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        tree_method="hist"
    )

    # Try sklearn-style fit with early_stopping_rounds (works on many installs)
    try:
        model.fit(
            X_train, y_train,
            eval_set=[(X_test, y_test)],
            early_stopping_rounds=20,
            verbose=False
        )
        y_pred = model.predict(X_test)
    except TypeError as e:
        # Fallback: use xgboost.train with DMatrix and early stopping
        logging.warning("sklearn .fit() with early_stopping_rounds failed (%s). Falling back to xgb.train()", str(e))
        dtrain = xgb.DMatrix(X_train, label=y_train)
        dtest = xgb.DMatrix(X_test, label=y_test)
        params = {
            "objective": "reg:squarederror",
            "learning_rate": 0.05,
            "max_depth": 6,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "tree_method": "hist",
            "seed": 42
        }
        evals = [(dtrain, "train"), (dtest, "eval")]
        bst = xgb.train(
            params,
            dtrain,
            num_boost_round=500,
            evals=evals,
            early_stopping_rounds=20,
            verbose_eval=False
        )
        # wrap trained booster into sklearn-compatible XGBRegressor for saving/usage
        model = xgb.XGBRegressor()
        model._Booster = bst
        model._le = None  # compatibility placeholder
        # predict using booster
        y_pred = bst.predict(dtest)

    r2 = r2_score(y_test, y_pred)
    rmse = mean_squared_error(y_test, y_pred, squared=False)

    # Save model: prefer joblib for sklearn wrapper; if we used booster, save booster directly
    try:
        joblib.dump(model, MODEL_PATH)
    except Exception:
        # fallback: save booster as binary
        if hasattr(model, "_Booster") and model._Booster is not None:
            booster_path = str(MODEL_PATH.with_suffix(".bst"))
            model._Booster.save_model(booster_path)
            logging.info("Saved booster to %s", booster_path)
        else:
            logging.warning("Could not joblib.dump model; no booster found.")

    return {"r2": float(r2), "rmse": float(rmse), "model_path": str(MODEL_PATH)}


def main():
    args = parse_args()
    simulate = args.simulate
    n_samples = args.n_samples

    logging.info("Starting dataset build simulate=%s n_samples=%d", simulate, n_samples)
    data = create_dataset(n_samples=n_samples, simulate=simulate)
    data.to_csv(DATA_CSV, index=False)
    logging.info("Dataset saved to %s shape=%s", DATA_CSV, data.shape)

    metrics = train_xgboost(data)
    logging.info("Training complete R2=%.3f RMSE=%.3f model=%s", metrics["r2"], metrics["rmse"], metrics["model_path"])
    print("R2:", metrics["r2"], "RMSE:", metrics["rmse"])
    print("Model saved to:", metrics["model_path"])


if __name__ == "__main__":
    main()