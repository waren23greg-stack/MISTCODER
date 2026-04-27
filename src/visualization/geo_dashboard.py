"""
geo_dashboard.py
Renders an interactive Folium map of Bio-Threat Units.
Output: dashboards/btu_map.html
"""
import folium
import pandas as pd
from pathlib import Path
from folium.plugins import MarkerCluster, HeatMap

TIER_COLORS = {"HIGH": "red", "MEDIUM": "orange", "LOW": "green"}

def build_map(scored_csv: Path, out_html: Path) -> None:
    df = pd.read_csv(scored_csv)
    df = df.dropna(subset=["location_lat", "location_lon", "risk_tier"])

    centre = [df["location_lat"].mean(), df["location_lon"].mean()]
    m = folium.Map(location=centre, zoom_start=5, tiles="CartoDB positron")

    # ── Heatmap layer ──────────────────────────────────────────────
    heat_data = df[["location_lat", "location_lon", "risk_score"]].values.tolist()
    HeatMap(heat_data, radius=18, blur=22,
            gradient={"0.33": "green", "0.66": "orange", "1.0": "red"},
            name="Risk Heatmap").add_to(m)

    # ── Clustered markers ──────────────────────────────────────────
    cluster = MarkerCluster(name="Incidents").add_to(m)
    for _, row in df.iterrows():
        color = TIER_COLORS.get(str(row["risk_tier"]), "gray")
        popup_html = f"""
        <b>{row['pathogen_name']}</b><br>
        Region: {row.get('region','—')}<br>
        Cases: {int(row['case_count'])}<br>
        NDVI: {row['ndvi_mean']:.3f}<br>
        Risk score: {row['risk_score']:.4f}<br>
        <span style='color:{color};font-weight:bold'>{row['risk_tier']}</span>
        """
        folium.CircleMarker(
            location=[row["location_lat"], row["location_lon"]],
            radius=6 + row["risk_score"] * 10,
            color=color, fill=True, fill_opacity=0.7,
            popup=folium.Popup(popup_html, max_width=220),
        ).add_to(cluster)

    # ── Layer control + title ──────────────────────────────────────
    folium.LayerControl().add_to(m)
    title_html = """
    <div style="position:fixed;top:10px;left:50%;transform:translateX(-50%);
                z-index:1000;background:white;padding:8px 16px;
                border-radius:6px;box-shadow:2px 2px 6px rgba(0,0,0,.3);
                font-family:sans-serif;font-size:15px;font-weight:bold;">
        🦠 EDEN-BioGuard — Bio-Threat Unit Map
    </div>"""
    m.get_root().html.add_child(folium.Element(title_html))

    out_html.parent.mkdir(parents=True, exist_ok=True)
    m.save(str(out_html))
    print(f"Dashboard saved → {out_html}")

if __name__ == "__main__":
    build_map(
        scored_csv=Path("data/synthetic/scored_outbreak.csv"),
        out_html=Path("dashboards/btu_map.html"),
    )
