"""
lab_intake.py
Ingests raw lab/community/environmental reports into a validated DataFrame.
Supports CSV, JSON, and dict payloads.
"""
import json
import logging
from pathlib import Path
from datetime import datetime
import pandas as pd

log = logging.getLogger(__name__)

REQUIRED_FIELDS = {"pathogen_name", "detection_date", "location_lat", "location_lon", "case_count", "source_type"}
VALID_SOURCE_TYPES = {"lab", "environmental", "community"}

def validate_record(record: dict) -> dict:
    missing = REQUIRED_FIELDS - set(record.keys())
    if missing:
        raise ValueError(f"Missing fields: {missing}")
    if record["source_type"] not in VALID_SOURCE_TYPES:
        raise ValueError(f"Invalid source_type: {record['source_type']}")
    record["detection_date"] = pd.to_datetime(record["detection_date"])
    record["case_count"]     = max(0, int(record["case_count"]))
    record["location_lat"]   = float(record["location_lat"])
    record["location_lon"]   = float(record["location_lon"])
    return record

def ingest(source) -> pd.DataFrame:
    """
    Accept a CSV path, JSON path, list of dicts, or single dict.
    Returns a clean, validated DataFrame.
    """
    if isinstance(source, (str, Path)):
        source = Path(source)
        if source.suffix == ".csv":
            raw = pd.read_csv(source).to_dict(orient="records")
        elif source.suffix == ".json":
            raw = json.loads(source.read_text())
        else:
            raise ValueError(f"Unsupported file type: {source.suffix}")
    elif isinstance(source, dict):
        raw = [source]
    elif isinstance(source, list):
        raw = source
    else:
        raise TypeError(f"Unsupported source type: {type(source)}")

    records, errors = [], []
    for i, rec in enumerate(raw):
        try:
            records.append(validate_record(dict(rec)))
        except Exception as e:
            errors.append((i, str(e)))
            log.warning("Row %d skipped: %s", i, e)

    if errors:
        log.warning("%d rows rejected out of %d", len(errors), len(raw))

    df = pd.DataFrame(records)
    log.info("Ingested %d valid records", len(df))
    return df

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    df = ingest(Path("data/synthetic/synthetic_outbreak.csv"))
    print(df.head())
    print(f"Shape: {df.shape}")
