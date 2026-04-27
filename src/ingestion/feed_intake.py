"""
feed_intake.py
Pulls live disease outbreak alerts from WHO & ProMED RSS feeds,
parses them into the standard BioGuard schema, and appends to
data/raw/live_incidents.csv
"""
import logging
import re
import hashlib
from datetime import datetime
from pathlib import Path

import feedparser
import pandas as pd
from bs4 import BeautifulSoup

log = logging.getLogger(__name__)

FEEDS = {
    # Africa CDC — Epidemic Intelligence tag feed (confirmed working)
    "AfricaCDC_Intel": "https://africacdc.org/tag/epidemic-intelligence/feed/",
    # WHO AFRO — Regional Office for Africa (confirmed working)
    "WHO_AFRO":        "https://www.afro.who.int/rss.xml",
}


# East Africa bounding box filter (lat -12 to 5, lon 28 to 42)
EA_BBOX = {"lat_min": -12, "lat_max": 5, "lon_min": 28, "lon_max": 42}

# Keywords to flag as biosecurity-relevant
BIO_KEYWORDS = [
    "outbreak", "disease", "virus", "fever", "cholera", "plague",
    "mpox", "ebola", "rift valley", "avian", "influenza", "anthrax",
    "leptospirosis", "meningitis", "dengue", "yellow fever",
]

# Known East Africa region mentions → rough centroid coords
REGION_COORDS = {
    "kenya":        (-1.286, 36.817),
    "nairobi":      (-1.286, 36.817),
    "uganda":       (0.348,  32.583),
    "kampala":      (0.348,  32.583),
    "tanzania":     (-6.369, 34.889),
    "dar es salaam":(-6.792, 39.208),
    "ethiopia":     (9.145,  40.490),
    "somalia":      (5.152,  46.200),
    "rwanda":       (-1.940, 29.874),
    "burundi":      (-3.373, 29.919),
    "south sudan":  (6.877,  31.307),
    "drc":          (-4.038, 21.759),
    "congo":        (-4.038, 21.759),
    "lamu":         (-2.269, 40.902),
    "mombasa":      (-4.043, 39.668),
    "kisumu":       (-0.092, 34.768),
    "garissa":      (-0.453, 39.646),
}


def _clean_html(raw: str) -> str:
    return BeautifulSoup(raw or "", "html.parser").get_text(" ", strip=True)


def _extract_pathogen(text: str) -> str:
    text_l = text.lower()
    for kw in BIO_KEYWORDS:
        if kw in text_l:
            return kw.title()
    return "Unknown"


def _extract_region(text: str):
    text_l = text.lower()
    for region, coords in REGION_COORDS.items():
        if region in text_l:
            return region.title(), coords[0], coords[1]
    return None, None, None


def _incident_id(url: str) -> str:
    return "FEED-" + hashlib.md5(url.encode()).hexdigest()[:8].upper()


def fetch_reliefweb() -> pd.DataFrame:
    """Fetch disease outbreak reports from ReliefWeb API v2 for East Africa."""
    import requests
    rows = []
    for country_name, iso in RELIEFWEB_COUNTRIES.items():
        try:
            resp = requests.post(
                RELIEFWEB_API,
                params={"appname": "eden-bioguard"},
                json={
                    "filter": {
                        "operator": "AND",
                        "conditions": [
                            {"field": "primary_country.iso3", "value": iso},
                            {"field": "theme.name", "value": "Health"},
                        ]
                    },
                    "fields": {"include": ["title", "date.created", "url", "body-html", "source.name"]},
                    "sort": ["date.created:desc"],
                    "limit": 10,
                },
                timeout=15,
            )
            resp.raise_for_status()
            for item in resp.json().get("data", []):
                f = item.get("fields", {})
                title   = f.get("title", "")
                summary = _clean_html(f.get("body-html", ""))[:300]
                full    = f"{title} {summary}".lower()
                if not any(kw in full for kw in BIO_KEYWORDS):
                    continue
                rows.append({
                    "incident_id":    _incident_id(item.get("href", title)),
                    "pathogen_name":  _extract_pathogen(full),
                    "detection_date": pd.to_datetime(f.get("date", {}).get("created", datetime.utcnow())),
                    "region":         country_name,
                    "location_lat":   REGION_COORDS.get(country_name.lower(), (None, None))[0],
                    "location_lon":   REGION_COORDS.get(country_name.lower(), (None, None))[1],
                    "case_count":     0,
                    "source_type":    "community",
                    "source_name":    "ReliefWeb",
                    "title":          title,
                    "summary":        summary,
                    "url":            f.get("url", ""),
                    "ndvi_mean":      None,
                    "tree_cover_pct": None,
                    "risk_score":     None,
                })
        except Exception as e:
            log.warning("ReliefWeb API failed for %s: %s", country_name, e)

    df = pd.DataFrame(rows)
    log.info("ReliefWeb: fetched %d relevant health reports", len(df))
    return df


def fetch_feeds(feeds: dict = FEEDS) -> pd.DataFrame:
    rows = []
    for source, url in feeds.items():
        log.info("Fetching %s feed: %s", source, url)
        try:
            import requests
            resp = requests.get(url, timeout=15,
                                headers={"User-Agent": "EDEN-BioGuard/1.0"})
            resp.raise_for_status()
            feed = feedparser.parse(resp.content)
        except Exception as e:
            log.warning("Failed to fetch %s: %s", source, e)
            continue

        if feed.bozo and not feed.entries:
            log.warning("%s feed bozo with no entries: %s", source, feed.bozo_exception)

        for entry in feed.entries:
            title   = entry.get("title", "")
            summary = _clean_html(entry.get("summary", entry.get("description", "")))
            full    = f"{title} {summary}".lower()

            # Filter: must contain at least one bio keyword
            if not any(kw in full for kw in BIO_KEYWORDS):
                continue

            region, lat, lon = _extract_region(full)

            rows.append({
                "incident_id":    _incident_id(entry.get("link", title)),
                "pathogen_name":  _extract_pathogen(full),
                "detection_date": datetime(*entry.published_parsed[:6]) if hasattr(entry, "published_parsed") and entry.published_parsed else datetime.utcnow(),
                "region":         region or "Unknown",
                "location_lat":   lat,
                "location_lon":   lon,
                "case_count":     0,          # feeds rarely include counts
                "source_type":    "community",
                "source_name":    source,
                "title":          title,
                "summary":        summary[:300],
                "url":            entry.get("link", ""),
                "ndvi_mean":      None,
                "tree_cover_pct": None,
                "risk_score":     None,
            })

    df = pd.DataFrame(rows)
    log.info("Fetched %d relevant alerts across %d feeds", len(df), len(feeds))
    return df


def save_live(df: pd.DataFrame, out: Path = Path("data/raw/live_incidents.csv")) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        existing = pd.read_csv(out)
        combined = pd.concat([existing, df]).drop_duplicates(subset=["incident_id"])
        combined.to_csv(out, index=False)
        log.info("Appended %d new rows → %s (total %d)", len(df), out, len(combined))
    else:
        df.to_csv(out, index=False)
        log.info("Created %s with %d rows", out, len(df))
    return out


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    df = fetch_feeds()
    if df.empty:
        print("No relevant alerts found — check network or feed URLs.")
    else:
        print(df[["source_name", "pathogen_name", "region",
                  "detection_date", "title"]].to_string(index=False))
        save_live(df)
        print(f"\nTotal live alerts: {len(df)}")
