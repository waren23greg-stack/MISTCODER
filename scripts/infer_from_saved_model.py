#!/usr/bin/env python3
import joblib
import pandas as pd
from pathlib import Path

MODEL = Path("artifacts/xgb_east_africa_yield.joblib")
DATA = Path("artifacts/dataset_east_africa.csv")

m = joblib.load(MODEL)
df = pd.read_csv(DATA)
X = df.drop(columns=["yield_t_ha"]).iloc[:5]
preds = m.predict(X)
print("Predictions:", preds)
