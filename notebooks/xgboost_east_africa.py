#!/usr/bin/env python3
"""
xgboost_east_africa.py
Train an XGBoost crop-yield model for East Africa using:
- Sentinel-2 NDVI via GEE (SIMULATE fallback)
- TAHMO rainfall/temperature (SIMULATE fallback)
- iSDA soil covariates (SIMULATE fallback)

Usage:
  # quick test with synthetic data
  python notebooks/xgboost_east_africa.py --simulate

  # real run (requires GEE auth and API keys)
  python notebooks/xgboost_east_africa.py
"""
import os
import time
import argparse
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import r2_score, mean_squared_error
import xgboost as xgb
import joblib
import logging

# Optional geospatial libs
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

# East Africa bbox
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
    if simulate:
        dates = pd.date_range(start=start_date, end=end_date, freq='M')
        df = pd.DataFrame({
            "date": dates,
            "ndvi_median": 0.2 + 0.4 * np.sin(np.linspace(0, 6*np.pi, len(dates))) + 0.05*np.random.randn(len(dates))
        })
        return df
    if not GEE_AVAILABLE:
        raise RuntimeError("GEE not available. Install earthengine-api and set simulate=True.")
    geom = ee.Geometry.BBox(*bbox)
    s2 = (ee.ImageCollection('COPERNICUS/S2_SR')
          .filterBounds(geom)
          .filterDate(start_date, end_date)
          .map(lambda img: img.normalizedDifference(['B8','B4']).rename('NDVI')))
    start = pd.to_datetime(start_date)
    end = pd.to_datetime(end_date)
    months = pd.date_range(start=start, end=end, freq='M')
    rows = []
    for m in months:
        m_start = ee.Date(m.replace(day=1).strftime('%Y-%m-%d'))
        m_end = ee.Date((m + pd.offsets.MonthEnd(0)).strftime('%Y-%m-%d'))
        img = s2.filterDate(m_start, m_end).median().select('NDVI')
        stat = img.reduceRegion(reducer=ee.Reducer.median(), geometry=geom, scale=1000, maxPixels=1e9)
        ndvi_val = stat.get('NDVI').getInfo() if stat.get('NDVI') else None
        rows.append({"date": m.to_pydatetime(), "ndvi_median": ndvi_val})
        time.sleep(0.15)
    df = pd.DataFrame(rows)
    df['ndvi_median'] = df['ndvi_median'].astype(float)
    return df

def fetch_tahmo_station_timeseries(station_id=None, bbox=None, start_date=START_DATE, end_date=END_DATE, simulate=True):
    if simulate:
        dates = pd.date_range(start=start_date, end=end_date, freq='M')
        df = pd.DataFrame({
            "date": dates,
            "rain_mm": 80 + 40*np.sin(np.linspace(0, 4*np.pi, len(dates))) + 10*np.random.randn(len(dates)),
            "temp_c": 20 + 3*np.sin(np.linspace(0, 2*np.pi, len(dates))) + 0.5*np.random.randn(len(dates))
        })
        return df
    api_key = os.getenv("TAHMO_API_KEY")
    if not api_key:
        raise RuntimeError("TAHMO_API_KEY not set. Use --simulate or set env var.")
    raise NotImplementedError("Real TAHMO client not implemented in this script.")

def fetch_isda_soil(lat, lon, simulate=True):
    if simulate:
        return {
            "soil_org_c": float(1.2 + 0.3*np.random.randn()),
            "soil_clay_pct": float(25 + 5*np.random.randn()),
            "soil_sand_pct": float(45 + 5*np.random.randn()),
            "soil_ph": float(6.2 + 0.3*np.random.randn())
        }
    api_key = os.getenv("ISDA_API_KEY")
    if not api_key:
        raise RuntimeError("ISDA_API_KEY not set. Use --simulate or set env var.")
    raise NotImplementedError("Real iSDA client not implemented in this script.")

def build_feature_table(bbox=EA_BBOX, start_date=START_DATE, end_date=END_DATE, simulate=True):
    ndvi_df = get_monthly_ndvi_timeseries_gee(bbox, start_date, end_date, simulate=simulate)
    tahmo_df = fetch_tahmo_station_timeseries(bbox=bbox, start_date=start_date, end_date=end_date, simulate=simulate)
    feats = {}
    feats['ndvi_mean'] = float(ndvi_df['ndvi_median'].mean())
    feats['ndvi_std'] = float(ndvi_df['ndvi_median'].std())
    feats['ndvi_max'] = float(ndvi_df['ndvi_median'].max())
    feats['ndvi_min'] = float(ndvi_df['ndvi_median'].min())
    feats['ndvi_amp'] = feats['ndvi_max'] - feats['ndvi_min']
    feats['rain_total'] = float(tahmo_df['rain_mm'].sum())
    feats['rain_mean'] = float(tahmo_df['rain_mm'].mean())
    feats['temp_mean'] = float(tahmo_df['temp_c'].mean())
    lon = (bbox[0] + bbox[2]) / 2.0
    lat = (bbox[1] + bbox[3]) / 2.0
    soil = fetch_isda_soil(lat, lon, simulate=simulate)
    feats.update(soil)
    if simulate:
        y = 1.5 + 3.0 * feats['ndvi_mean'] + 0.002 * feats['rain_total'] + 0.1 * feats['soil_org_c'] + np.random.randn()*0.3
        feats['yield_t_ha'] = float(y)
        return pd.DataFrame([feats])
    raise NotImplementedError("Real yield ingestion not implemented. Provide ground truth or use simulate.")

def create_dataset(n_samples=300, simulate=True):
    rows = []
    for i in range(n_samples):
        dx = np.random.uniform(-1.0, 1.0)
        dy = np.random.uniform(-1.0, 1.0)
        bbox = [EA_BBOX[0]+dx, EA_BBOX[1]+dy, EA_BBOX[2]+dx, EA_BBOX[3]+dy]
        df = build_feature_table(bbox=bbox, simulate=simulate)
        rows.append(df.iloc[0])
    dataset = pd.DataFrame(rows)
    return dataset

def train_xgboost(data):
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
        tree_method='hist'
    )
    model.fit(X_train, y_train, eval_set=[(X_test, y_test)], early_stopping_rounds=20, verbose=False)
    y_pred = model.predict(X_test)
    r2 = r2_score(y_test, y_pred)
    rmse = mean_squared_error(y_test, y_pred, squared=False)
    joblib.dump(model, MODEL_PATH)
    return {"r2": float(r2), "rmse": float(rmse), "model_path": str(MODEL_PATH)}

def main():
    args = parse_args()
    simulate = args.simulate
    logging.info("Building dataset simulate=%s n_samples=%d", simulate, args.n_samples)
    data = create_dataset(n_samples=args.n_samples, simulate=simulate)
    data.to_csv(DATA_CSV, index=False)
    logging.info("Dataset saved to %s shape=%s", DATA_CSV, data.shape)
    metrics = train_xgboost(data)
    logging.info("Training complete R2=%.3f RMSE=%.3f model=%s", metrics['r2'], metrics['rmse'], metrics['model_path'])
    print("R2:", metrics['r2'], "RMSE:", metrics['rmse'])
    print("Model saved to:", metrics['model_path'])

if __name__ == "__main__":
    main()
