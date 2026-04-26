"""
BioGuard Dossier Generator
===========================
Produces structured evidence dossiers for each flagged entity.
Output format is designed to be submitted to:
  - Kenya Directorate of Criminal Investigations (DCI)
  - Kenya Forest Service (KFS) Enforcement Unit
  - INTERPOL Wildlife Crime Unit (Project Predator)
  - Verra / Gold Standard Carbon Registry auditors
  - UNFCCC Integrity Unit
  - Investigative journalists (structured data for publishing)
"""

import json
from datetime import datetime, timezone
from pathlib import Path


REFERRAL_DESCRIPTIONS = {
    "DCI_KENYA": "Kenya Directorate of Criminal Investigations — Economic Crimes Unit",
    "KFS_ENFORCEMENT": "Kenya Forest Service — Forest Protection & Enforcement",
    "INTERPOL_WILDLIFE": "INTERPOL — Project Predator (Wildlife & Forest Crime)",
    "INTERPOL_FINANCIAL_CRIMES": "INTERPOL — Financial Crimes Sub-Directorate",
    "CARBON_REGISTRY_VERRA": "Verra VCS Carbon Registry — Integrity & Audit Division",
    "UNFCCC_INTEGRITY": "UNFCCC — Article 6 Carbon Market Integrity Unit",
    "FINANCIAL_INTELLIGENCE_UNIT": "Kenya Financial Intelligence Centre (KFIC)",
    "SATELLITE_EVIDENCE_UNIT": "Regional Centre for Mapping of Resources for Development (RCMRD)",
}

THREAT_DESCRIPTIONS = {
    "CARBON_FRAUD": (
        "Entity is filing carbon credits for forest carbon that does not exist "
        "or has been destroyed. Credits represent fraudulent financial instruments "
        "on international carbon markets."
    ),
    "LAND_GRAB": (
        "Entity has acquired or is clearing land under a conservation title. "
        "Pattern of rectangular, systematic clearing indicates commercial extraction "
        "rather than natural disturbance."
    ),
    "POACHING_NETWORK": (
        "Acoustic and thermal signatures indicate organized wildlife crime activity "
        "inside a registered conservation area. Gunshot events and night vehicle "
        "movement suggest commercial poaching logistics."
    ),
    "SHELL_CONSERVANCY": (
        "Entity bears characteristics of a shell structure: recently registered, "
        "opaque beneficial ownership, linked to extraction companies, with minimal "
        "legitimate conservation activity."
    ),
    "MONEY_LAUNDERING": (
        "Carbon credit payments and conservation funding flows to offshore accounts "
        "inconsistent with legitimate conservation operations. Pattern suggests "
        "carbon markets are being used to launder extraction proceeds."
    ),
    "NETWORK": (
        "Confirmed directorial, financial, or operational links between flagged "
        "entities suggest coordinated activity across multiple shell structures."
    ),
}


def generate_dossiers(report_path: str = "reports/bioguard_report.json",
                      output_dir: str = "reports/dossiers") -> list[dict]:
    """Generate individual evidence dossiers from BioGuard scan report."""

    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    dossiers_out = []
    now = datetime.now(timezone.utc).isoformat()

    for entity_name, data in report.get("dossiers", {}).items():
        entity   = data["entity"]
        grade    = entity.get("evidence_grade", "SUSPECTED")
        score    = entity.get("contradiction_score", 0)
        block_ref = data.get("block_ref", "—")

        # Gather all blocks referencing this entity
        linked_blocks = [
            b for b in report.get("blocks", [])
            if entity_name in b.get("entity", "")
        ]

        # Gather behavioral signals
        signals = [
            s for s in report.get("behavioral_signals", [])
            if s.get("entity_name") == entity_name
        ]

        # Gather network links
        links = [
            l for l in report.get("actor_network", [])
            if entity_name in (l.get("actor_a"), l.get("actor_b"))
        ]

        fraud_credits = data.get("fraud_credits", 0)
        referred_to   = data.get("referred_to", [])

        dossier = {
            "dossier_id"         : f"BG-{entity.get('registration_number', 'UNKNOWN')}",
            "generated_at"       : now,
            "classification"     : "RESTRICTED — ENFORCEMENT USE",
            "evidence_grade"     : grade,
            "contradiction_score": score,

            "subject": {
                "name"                   : entity_name,
                "registration_number"    : entity.get("registration_number"),
                "registered_date"        : entity.get("registered_date"),
                "registered_country"     : entity.get("registered_country"),
                "directors"              : entity.get("directors", []),
                "beneficial_owner"       : entity.get("beneficial_owner"),
                "offshore_accounts"      : entity.get("offshore_accounts", []),
                "linked_entities"        : entity.get("linked_entities", []),
                "mining_logging_licenses": entity.get("mining_licenses", []),
            },

            "conservation_claim": {
                "land_title_ha"              : entity.get("land_title_ha"),
                "conservation_claim_ha"      : entity.get("conservation_claim_ha"),
                "carbon_credits_filed"       : entity.get("carbon_credits_filed"),
                "carbon_credits_legitimate"  : entity.get("carbon_credits_legitimate"),
                "fraudulent_credits_estimated": fraud_credits,
                "estimated_fraud_value_usd"  : fraud_credits * 15,
            },

            "threat_assessment": {
                "primary_threat"   : linked_blocks[0].get("threat_class") if linked_blocks else "UNKNOWN",
                "threat_description": THREAT_DESCRIPTIONS.get(
                    linked_blocks[0].get("threat_class", ""), ""
                ) if linked_blocks else "",
                "behavioral_signals": [
                    {
                        "signal_type"          : s.get("signal_type"),
                        "region"               : s.get("region"),
                        "parcel_id"            : s.get("parcel_id"),
                        "ndvi_claimed"         : s.get("ndvi_claimed"),
                        "ndvi_satellite"       : s.get("ndvi_actual"),
                        "ndvi_divergence"      : s.get("ndvi_delta"),
                        "clearing_ha_per_month": s.get("clearing_rate_ha_per_month"),
                        "night_activity"       : s.get("night_activity_detected"),
                        "rectangular_clearing" : s.get("rectangular_clearing"),
                        "acoustic_gunshots"    : s.get("acoustic_gunshot_events"),
                        "thermal_anomalies"    : s.get("thermal_anomalies"),
                        "severity"             : s.get("severity"),
                    }
                    for s in signals
                ],
            },

            "network_links": [
                {
                    "connected_to" : l.get("actor_b") if l.get("actor_a") == entity_name
                                     else l.get("actor_a"),
                    "link_type"    : l.get("link_type"),
                    "strength"     : l.get("strength"),
                    "evidence"     : l.get("evidence"),
                }
                for l in links
            ],

            "blockchain_evidence": {
                "primary_block"  : block_ref,
                "all_blocks"     : [b.get("block_index") for b in linked_blocks],
                "block_hashes"   : [b.get("block_hash") for b in linked_blocks],
                "chain_timestamp": linked_blocks[0].get("timestamp") if linked_blocks else now,
                "tamper_proof"   : True,
                "ledger"         : "MistChain — PhantomChainBridge / NODE-PRIMARY",
            },

            "referrals": [
                {
                    "agency"     : agency,
                    "description": REFERRAL_DESCRIPTIONS.get(agency, agency),
                    "priority"   : "URGENT" if score >= 9.0 else "HIGH" if score >= 7.0 else "STANDARD",
                    "status"     : "PENDING_SUBMISSION",
                }
                for agency in referred_to
            ],

            "recommended_actions": _recommend_actions(score, fraud_credits, entity),
        }

        # Save individual dossier
        safe_name = entity_name.replace(" ", "_").replace("/", "-")[:50]
        dossier_path = Path(output_dir) / f"{safe_name}.json"
        dossier_path.write_text(json.dumps(dossier, indent=2), encoding="utf-8")
        dossiers_out.append(dossier)

        grade_sym = "🔴" if grade == "CONFIRMED" else "🟡" if grade == "PROBABLE" else "🟢"
        print(f"  {grade_sym} Dossier: {entity_name[:45]} → {dossier_path.name}")

    # Write master index
    index = {
        "generated_at"   : now,
        "total_dossiers" : len(dossiers_out),
        "confirmed"      : sum(1 for d in dossiers_out if d["evidence_grade"] == "CONFIRMED"),
        "probable"       : sum(1 for d in dossiers_out if d["evidence_grade"] == "PROBABLE"),
        "dossiers"       : [
            {
                "id"                : d["dossier_id"],
                "entity"            : d["subject"]["name"],
                "grade"             : d["evidence_grade"],
                "score"             : d["contradiction_score"],
                "fraud_credits_usd" : d["conservation_claim"]["estimated_fraud_value_usd"],
                "referral_count"    : len(d["referrals"]),
            }
            for d in dossiers_out
        ]
    }
    (Path(output_dir) / "INDEX.json").write_text(
        json.dumps(index, indent=2), encoding="utf-8"
    )
    print(f"\n[BIOGUARD] {len(dossiers_out)} dossiers saved → {output_dir}/")
    return dossiers_out


def _recommend_actions(score: float, fraud_credits: int, entity: dict) -> list[str]:
    actions = []
    if score >= 9.0:
        actions.append("IMMEDIATE: Freeze carbon credit issuance pending investigation")
        actions.append("IMMEDIATE: Alert KFS for ground-truthing aerial survey")
        actions.append("URGENT: Submit evidence package to DCI Economic Crimes Unit")
        actions.append("URGENT: Notify INTERPOL Project Predator if wildlife crime confirmed")
    if score >= 7.0:
        actions.append("HIGH: Refer to Verra/Gold Standard for credit suspension")
        actions.append("HIGH: Conduct beneficial ownership tracing via KFIC")
    if entity.get("offshore_accounts"):
        actions.append("Flag offshore account chain to Financial Intelligence Centre")
    if entity.get("mining_licenses"):
        actions.append("Cross-check mining/logging licenses with Ministry of Environment")
    if entity.get("linked_entities"):
        actions.append("Expand investigation to all linked entities in network")
    if fraud_credits > 10000:
        actions.append(
            f"Quantify financial exposure: ~{fraud_credits:,} credits × $15 = "
            f"${fraud_credits * 15:,.0f} estimated fraud value"
        )
    return actions


if __name__ == "__main__":
    print("[BIOGUARD] Generating enforcement dossiers...")
    generate_dossiers()
