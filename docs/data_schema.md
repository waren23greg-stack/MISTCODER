# EDEN-BioGuard Data Schema

## pathogen_incidents
| field            | type      | description                          |
|------------------|-----------|--------------------------------------|
| incident_id      | UUID      | Unique event identifier              |
| pathogen_name    | VARCHAR   | Species / strain                     |
| detection_date   | DATE      | First confirmed detection            |
| location_lat     | FLOAT     | Decimal latitude                     |
| location_lon     | FLOAT     | Decimal longitude                    |
| admin_region     | VARCHAR   | District / county                    |
| case_count       | INT       | Confirmed cases at detection         |
| source_type      | ENUM      | lab | environmental | community        |
| sequencing_id    | VARCHAR   | Link to genomic record (optional)    |

## ecosystem_health
| field            | type      | description                          |
|------------------|-----------|--------------------------------------|
| site_id          | UUID      | Monitoring site                      |
| site_type        | ENUM      | mangrove | forest | wetland | urban  |
| ndvi_mean        | FLOAT     | Vegetation index (Sentinel-2)        |
| tree_cover_pct   | FLOAT     | Canopy coverage %                    |
| water_proximity  | FLOAT     | Distance to water body (km)          |
| restoration_date | DATE      | If EDEN reforestation site           |

## bio_threat_units
| field            | type      | description                          |
|------------------|-----------|--------------------------------------|
| btu_id           | UUID      | Computed risk unit                   |
| incident_id      | FK        | → pathogen_incidents                 |
| site_id          | FK        | → ecosystem_health                   |
| risk_score       | FLOAT     | 0–1 composite risk index             |
| forecast_date    | DATE      | Prediction horizon                   |
