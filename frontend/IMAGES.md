# EDEN × MISTCODER Frontend — Image Setup

Drop these free images into the `images/` folder.
All are free to use (Unsplash License — no attribution required for most uses).

## Required images

| File | Source | Search term |
|------|--------|-------------|
| `kenya-aerial.jpg` | unsplash.com | "kenya aerial forest" |
| `mau-forest.jpg`   | unsplash.com | "mau forest canopy" or "tropical forest aerial" |
| `rift-valley.jpg`  | unsplash.com | "rift valley kenya aerial" or "savanna aerial" |
| `nairobi.jpg`      | unsplash.com | "nairobi city aerial" |

## Quick download (direct Unsplash links — pick any you like)

- Forest canopy: https://unsplash.com/photos/Hli3R6LKibo
- Aerial savanna: https://unsplash.com/photos/o0RZkkL0Jwc  
- Nairobi city:  https://unsplash.com/photos/7nrsVjvALnA
- Kenya aerial:  https://unsplash.com/photos/t1XLQvbaa7o

## NASA free satellite imagery (public domain, no restrictions)

Kenya Landsat composite:
https://worldview.earthdata.nasa.gov/?v=33.0,-5.0,42.5,5.0&l=MODIS_Terra_CorrectedReflectance_TrueColor

## If images are missing

The dashboard shows SVG fallbacks automatically — hand-drawn
satellite-style illustrations of each region. The dashboard
works 100% without the images, just looks better with them.

## Live data

Copy `reports/bio_tokens.json` and `reports/eden_report.json`
from your MISTCODER repo root into `data/` to enable live token loading:

  cp ../reports/bio_tokens.json data/
  cp ../reports/eden_report.json data/

Then run the dashboard with any static server:

  python -m http.server 8080
  # open http://localhost:8080
