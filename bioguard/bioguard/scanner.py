"""
BioGuard Intelligence Scanner
==============================
Three-layer conservation fraud detection system:

  Layer 1 — Corporate Veil Piercer
            Who really owns the land claiming conservation status?

  Layer 2 — Behavioral Contradiction Engine
            Does what they claim match what the satellite sees?

  Layer 3 — Actor Network Graph
            Who is connected to whom across shell companies,
            poaching networks, and fraudulent carbon claims?

Each confirmed signal produces a VIOLATION, ACTOR, FRAUD, or NETWORK
block on the MistChain ledger — immutable, timestamped, court-ready.
"""

import hashlib
import json
import random
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional


# ── Enums ──────────────────────────────────────────────────────────────

class ThreatClass(Enum):
    CARBON_FRAUD      = "CARBON_FRAUD"        # Claiming credits on dead/cleared forest
    LAND_GRAB         = "LAND_GRAB"           # Illegal acquisition under conservation veil
    POACHING_NETWORK  = "POACHING_NETWORK"    # Commercial poaching logistics
    SHELL_CONSERVANCY = "SHELL_CONSERVANCY"   # Fake NGO fronting extraction
    INSIDER_COLLUSION = "INSIDER_COLLUSION"   # Rangers/officials enabling crime
    MONEY_LAUNDERING  = "MONEY_LAUNDERING"    # Carbon credits as financial instrument
    BOUNDARY_VIOLATION= "BOUNDARY_VIOLATION"  # Active illegal clearing in protected zone

class EvidenceGrade(Enum):
    CONFIRMED  = "CONFIRMED"    # Multiple independent signals agree
    PROBABLE   = "PROBABLE"     # Strong pattern, one signal missing
    SUSPECTED  = "SUSPECTED"    # Early signal, monitoring escalated
    CLEARED    = "CLEARED"      # Investigation resolved — legitimate actor


# ── Data structures ────────────────────────────────────────────────────

@dataclass
class CorporateEntity:
    name: str
    registration_number: str
    registered_date: str
    registered_country: str
    directors: list[str]
    beneficial_owner: str          # "UNKNOWN" if hidden offshore
    land_title_ha: float
    conservation_claim_ha: float
    carbon_credits_filed: int
    carbon_credits_legitimate: int
    offshore_accounts: list[str]
    linked_entities: list[str]     # Other companies sharing directors/addresses
    mining_licenses: list[str]     # Active mining/logging licenses held
    contradiction_score: float     # 0-10: how badly claims vs reality diverge
    evidence_grade: EvidenceGrade

@dataclass
class BehavioralSignal:
    entity_name: str
    signal_type: str
    region: str
    parcel_id: str
    detected_at: str
    ndvi_claimed: float            # What they report in carbon filings
    ndvi_actual: float             # What satellite shows
    ndvi_delta: float              # Divergence
    clearing_rate_ha_per_month: float
    night_activity_detected: bool
    vehicle_tracks_detected: bool
    rectangular_clearing: bool     # Signature of commercial, not natural
    thermal_anomalies: int         # Night heat sources in protected zone
    acoustic_gunshot_events: int
    severity: float                # 0-10

@dataclass
class ActorLink:
    actor_a: str
    actor_b: str
    link_type: str    # SHARED_DIRECTOR | SHARED_ADDRESS | FINANCIAL_FLOW | SAME_PARCEL
    strength: float   # 0-1
    evidence: str

@dataclass
class ViolationBlock:
    block_index: int
    block_hash: str
    block_type: str                # VIOLATION | ACTOR | FRAUD | NETWORK
    threat_class: str
    entity: str
    region: str
    parcel_id: str
    summary: str
    contradiction_score: float
    evidence_grade: str
    carbon_credits_at_risk: int
    land_ha: float
    dossier_ref: str
    timestamp: str
    linked_blocks: list[int]
    referred_to: list[str]         # DCI | KFS | INTERPOL | CARBON_REGISTRY


# ── Synthetic intelligence data (real-world pattern archetypes) ────────

SYNTHETIC_ENTITIES = [
    {
        "name": "GreenVeil Conservation Partners Ltd",
        "registration_number": "CPK/2023/04471",
        "registered_date": "2023-03-14",
        "registered_country": "Kenya (BVI beneficial)",
        "directors": ["Thomas Reinholt", "Amina Osei-Bonsu", "D. Whitmore"],
        "beneficial_owner": "UNKNOWN — British Virgin Islands",
        "land_title_ha": 2840.0,
        "conservation_claim_ha": 2840.0,
        "carbon_credits_filed": 34200,
        "carbon_credits_legitimate": 1800,
        "offshore_accounts": ["BVI-TRUST-447", "SEYCHELLES-GL-09"],
        "linked_entities": ["Veil Timber Holdings", "GV Agriforest Kenya"],
        "mining_licenses": ["MINING/MAU/2022/117"],
        "contradiction_score": 9.4,
        "evidence_grade": EvidenceGrade.CONFIRMED,
    },
    {
        "name": "Rift Stewardship Foundation",
        "registration_number": "NGO/2021/11892",
        "registered_date": "2021-07-02",
        "registered_country": "Kenya",
        "directors": ["Grace Mutua", "P. Eriksson", "James Wanjohi"],
        "beneficial_owner": "P. Eriksson (Swedish national, resident Dubai)",
        "land_title_ha": 1200.0,
        "conservation_claim_ha": 1200.0,
        "carbon_credits_filed": 18600,
        "carbon_credits_legitimate": 12400,
        "offshore_accounts": ["UAE-HOLDING-882"],
        "linked_entities": ["Rift Eco-Safari Ltd", "Nordic Carbon Brokers AS"],
        "mining_licenses": [],
        "contradiction_score": 6.1,
        "evidence_grade": EvidenceGrade.PROBABLE,
        "note": "Safari revenue declared, carbon credit diversion suspected"
    },
    {
        "name": "Eastlands Urban Forest Trust",
        "registration_number": "NGO/2020/08834",
        "registered_date": "2020-01-15",
        "registered_country": "Kenya",
        "directors": ["Boniface Kamau", "Roselyn Achieng"],
        "beneficial_owner": "Boniface Kamau",
        "land_title_ha": 408.0,
        "conservation_claim_ha": 408.0,
        "carbon_credits_filed": 6200,
        "carbon_credits_legitimate": 5800,
        "offshore_accounts": [],
        "linked_entities": [],
        "mining_licenses": [],
        "contradiction_score": 1.2,
        "evidence_grade": EvidenceGrade.CLEARED,
        "note": "Legitimate community trust — cleared after investigation"
    },
    {
        "name": "SilverLeaf Carbon Investments",
        "registration_number": "CMP/2022/33019",
        "registered_date": "2022-11-28",
        "registered_country": "Mauritius (Kenya operations)",
        "directors": ["Ravi Menon", "Clara Oduya", "H. Stenmark", "T. Reinholt"],
        "beneficial_owner": "UNKNOWN — Mauritius trust chain",
        "land_title_ha": 5100.0,
        "conservation_claim_ha": 4800.0,
        "carbon_credits_filed": 61000,
        "carbon_credits_legitimate": 4200,
        "offshore_accounts": ["MAURITIUS-SL-001", "MAURITIUS-SL-002", "SINGAPORE-SL-T"],
        "linked_entities": ["GreenVeil Conservation Partners Ltd", "SL Agri Rift Ltd"],
        "mining_licenses": ["MINING/RIFT/2023/044", "LOGGING/MAU/2021/088"],
        "contradiction_score": 9.8,
        "evidence_grade": EvidenceGrade.CONFIRMED,
        "note": "T. Reinholt also director of GreenVeil — network confirmed"
    },
    {
        "name": "Mau Indigenous Communities Alliance",
        "registration_number": "CBO/2018/00341",
        "registered_date": "2018-04-20",
        "registered_country": "Kenya",
        "directors": ["Cheruiyot Kipkoech", "Margaret Chepkemoi", "David Ng'etich"],
        "beneficial_owner": "Community CBO — 847 registered members",
        "land_title_ha": 3200.0,
        "conservation_claim_ha": 3200.0,
        "carbon_credits_filed": 38000,
        "carbon_credits_legitimate": 37200,
        "offshore_accounts": [],
        "linked_entities": [],
        "mining_licenses": [],
        "contradiction_score": 0.4,
        "evidence_grade": EvidenceGrade.CLEARED,
        "note": "Genuine community forest steward. Carbon revenue returns to members."
    },
    {
        "name": "Continental Wildlife Corridor Fund",
        "registration_number": "INTL/2023/KE/00871",
        "registered_date": "2023-01-09",
        "registered_country": "Kenya (Delaware USA parent)",
        "directors": ["M. Ashworth", "Fatuma Issa", "C. Bauer", "Ravi Menon"],
        "beneficial_owner": "UNKNOWN — Delaware LLC chain → Panama",
        "land_title_ha": 7200.0,
        "conservation_claim_ha": 7200.0,
        "carbon_credits_filed": 94000,
        "carbon_credits_legitimate": 3100,
        "offshore_accounts": ["DELAWARE-CWC-LLC", "PANAMA-HOLDING-07", "CAYMAN-CWC-T"],
        "linked_entities": ["SilverLeaf Carbon Investments", "Rift Stewardship Foundation",
                            "Continental Agri-Rift SA", "Pan-Africa Timber Corp"],
        "mining_licenses": ["LOGGING/MAU/2023/012", "LOGGING/RIFT/2022/091",
                            "MINING/COAST/2023/034"],
        "contradiction_score": 9.9,
        "evidence_grade": EvidenceGrade.CONFIRMED,
        "note": "APEX NODE: Ravi Menon links this entity to SilverLeaf. "
                "M. Ashworth linked to Pan-Africa Timber. "
                "94k carbon credits filed on land with 67% NDVI loss."
    },
]

BEHAVIORAL_SIGNALS = [
    {
        "entity_name": "GreenVeil Conservation Partners Ltd",
        "signal_type": "NDVI_FRAUD",
        "region": "Mau Forest",
        "parcel_id": "MAU/N/2840/KFS",
        "ndvi_claimed": 0.72,
        "ndvi_actual": 0.31,
        "ndvi_delta": -0.41,
        "clearing_rate_ha_per_month": 38.4,
        "night_activity_detected": True,
        "vehicle_tracks_detected": True,
        "rectangular_clearing": True,
        "thermal_anomalies": 14,
        "acoustic_gunshot_events": 6,
        "severity": 9.4,
    },
    {
        "entity_name": "SilverLeaf Carbon Investments",
        "signal_type": "MASS_CLEARING",
        "region": "Rift Valley",
        "parcel_id": "RIFT/S/5100/KLC",
        "ndvi_claimed": 0.68,
        "ndvi_actual": 0.22,
        "ndvi_delta": -0.46,
        "clearing_rate_ha_per_month": 127.0,
        "night_activity_detected": True,
        "vehicle_tracks_detected": True,
        "rectangular_clearing": True,
        "thermal_anomalies": 31,
        "acoustic_gunshot_events": 0,
        "severity": 9.8,
    },
    {
        "entity_name": "Continental Wildlife Corridor Fund",
        "signal_type": "SYSTEMATIC_EXTRACTION",
        "region": "Mau Forest",
        "parcel_id": "MAU/S/7200/INTL",
        "ndvi_claimed": 0.74,
        "ndvi_actual": 0.24,
        "ndvi_delta": -0.50,
        "clearing_rate_ha_per_month": 204.0,
        "night_activity_detected": True,
        "vehicle_tracks_detected": True,
        "rectangular_clearing": True,
        "thermal_anomalies": 58,
        "acoustic_gunshot_events": 22,
        "severity": 9.9,
    },
    {
        "entity_name": "Rift Stewardship Foundation",
        "signal_type": "PARTIAL_DIVERSION",
        "region": "Rift Valley",
        "parcel_id": "RIFT/N/1200/NGO",
        "ndvi_claimed": 0.61,
        "ndvi_actual": 0.48,
        "ndvi_delta": -0.13,
        "clearing_rate_ha_per_month": 8.2,
        "night_activity_detected": False,
        "vehicle_tracks_detected": True,
        "rectangular_clearing": False,
        "thermal_anomalies": 3,
        "acoustic_gunshot_events": 0,
        "severity": 6.1,
    },
]

ACTOR_LINKS = [
    {"actor_a": "GreenVeil Conservation Partners Ltd",
     "actor_b": "SilverLeaf Carbon Investments",
     "link_type": "SHARED_DIRECTOR",
     "strength": 0.95,
     "evidence": "Thomas Reinholt appears as director on both entities"},
    {"actor_a": "SilverLeaf Carbon Investments",
     "actor_b": "Continental Wildlife Corridor Fund",
     "link_type": "SHARED_DIRECTOR",
     "strength": 0.95,
     "evidence": "Ravi Menon appears as director on both entities"},
    {"actor_a": "Continental Wildlife Corridor Fund",
     "actor_b": "Pan-Africa Timber Corp",
     "link_type": "FINANCIAL_FLOW",
     "strength": 0.88,
     "evidence": "Carbon credit payments traced to Pan-Africa Timber accounts"},
    {"actor_a": "GreenVeil Conservation Partners Ltd",
     "actor_b": "Veil Timber Holdings",
     "link_type": "SHARED_ADDRESS",
     "strength": 0.91,
     "evidence": "Registered address: Suite 4B, Waiyaki Way, Nairobi — identical"},
    {"actor_a": "SilverLeaf Carbon Investments",
     "actor_b": "Continental Wildlife Corridor Fund",
     "link_type": "FINANCIAL_FLOW",
     "strength": 0.82,
     "evidence": "Mauritius → Panama offshore flow pattern matches both entities"},
    {"actor_a": "Continental Wildlife Corridor Fund",
     "actor_b": "Rift Stewardship Foundation",
     "link_type": "SAME_PARCEL",
     "strength": 0.74,
     "evidence": "Overlapping carbon credit claims on parcel RIFT/N/1200/NGO"},
]


# ── Scanner engine ─────────────────────────────────────────────────────

class BioGuardScanner:

    def __init__(self, chain_start_index: int = 109):
        self.chain_index = chain_start_index
        self.blocks: list[ViolationBlock] = []
        self.entities: list[CorporateEntity] = []
        self.signals: list[BehavioralSignal] = []
        self.network: list[ActorLink] = []
        self.dossiers: dict = {}

    def _hash(self, data: dict) -> str:
        raw = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()

    def _ts(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _mint_block(self, block_type: str, threat_class: str, entity: str,
                    region: str, parcel_id: str, summary: str,
                    contradiction_score: float, evidence_grade: str,
                    carbon_at_risk: int, land_ha: float,
                    dossier_ref: str, linked: list[int],
                    referred_to: list[str]) -> ViolationBlock:

        idx = self.chain_index
        self.chain_index += 1
        ts  = self._ts()
        h   = self._hash({"idx": idx, "entity": entity, "ts": ts,
                           "threat": threat_class})[:16]

        block = ViolationBlock(
            block_index          = idx,
            block_hash           = h,
            block_type           = block_type,
            threat_class         = threat_class,
            entity               = entity,
            region               = region,
            parcel_id            = parcel_id,
            summary              = summary,
            contradiction_score  = contradiction_score,
            evidence_grade       = evidence_grade,
            carbon_credits_at_risk = carbon_at_risk,
            land_ha              = land_ha,
            dossier_ref          = dossier_ref,
            timestamp            = ts,
            linked_blocks        = linked,
            referred_to          = referred_to,
        )
        self.blocks.append(block)
        return block

    # ── Layer 1: Corporate Veil Piercer ───────────────────────────────

    def pierce_corporate_veil(self) -> list[CorporateEntity]:
        print("\n[BIOGUARD-L1] Corporate Veil Piercer — scanning entity registry...")
        results = []

        for raw in SYNTHETIC_ENTITIES:
            note = raw.pop("note", "")
            entity = CorporateEntity(**raw)
            self.entities.append(entity)

            if entity.evidence_grade == EvidenceGrade.CLEARED:
                print(f"  [CLEARED]   {entity.name}")
                continue

            fraud_credits = entity.carbon_credits_filed - entity.carbon_credits_legitimate
            offshore_flag = entity.beneficial_owner.startswith("UNKNOWN")
            multi_license = len(entity.mining_licenses) > 0
            linked_count  = len(entity.linked_entities)

            # Determine referral agencies
            referred = []
            if entity.contradiction_score >= 8.0:
                referred = ["DCI_KENYA", "KFS_ENFORCEMENT", "INTERPOL_WILDLIFE",
                            "CARBON_REGISTRY_VERRA", "UNFCCC_INTEGRITY"]
            elif entity.contradiction_score >= 6.0:
                referred = ["KFS_ENFORCEMENT", "CARBON_REGISTRY_VERRA"]
            else:
                referred = ["KFS_MONITORING"]

            dossier_ref = f"BG-DOSSIER-{entity.registration_number}"

            block = self._mint_block(
                block_type           = "ACTOR",
                threat_class         = ThreatClass.CARBON_FRAUD.value if fraud_credits > 5000
                                       else ThreatClass.SHELL_CONSERVANCY.value,
                entity               = entity.name,
                region               = "Multiple" if linked_count > 1 else "Kenya",
                parcel_id            = entity.registration_number,
                summary              = (
                    f"Entity claims {entity.conservation_claim_ha:.0f}ha conservation. "
                    f"Filed {entity.carbon_credits_filed:,} carbon credits, "
                    f"legitimate: {entity.carbon_credits_legitimate:,}. "
                    f"Offshore: {'YES' if offshore_flag else 'NO'}. "
                    f"Mining licenses: {len(entity.mining_licenses)}. "
                    f"Linked entities: {linked_count}. "
                    f"Contradiction score: {entity.contradiction_score}/10."
                ),
                contradiction_score  = entity.contradiction_score,
                evidence_grade       = entity.evidence_grade.value,
                carbon_at_risk       = fraud_credits,
                land_ha              = entity.land_title_ha,
                dossier_ref          = dossier_ref,
                linked               = [],
                referred_to          = referred,
            )

            self.dossiers[entity.name] = {
                "entity":           asdict(entity),
                "block_ref":        block.block_index,
                "fraud_credits":    fraud_credits,
                "offshore":         offshore_flag,
                "mining_licenses":  multi_license,
                "referred_to":      referred,
                "note":             note,
            }

            grade_label = entity.evidence_grade.value
            print(f"  [{grade_label:9}] {entity.name[:45]:45} score={entity.contradiction_score} "
                  f"fraud_credits={fraud_credits:,} block=#{block.block_index}")
            results.append(entity)

        return results

    # ── Layer 2: Behavioral Contradiction Engine ───────────────────────

    def run_contradiction_engine(self) -> list[BehavioralSignal]:
        print("\n[BIOGUARD-L2] Behavioral Contradiction Engine — NDVI vs claims...")
        results = []

        for raw in BEHAVIORAL_SIGNALS:
            sig = BehavioralSignal(
                detected_at = self._ts(),
                **raw
            )
            self.signals.append(sig)

            # Find linked actor block
            linked_blocks = [b.block_index for b in self.blocks
                             if b.entity == sig.entity_name]

            threat = ThreatClass.CARBON_FRAUD.value
            if sig.acoustic_gunshot_events > 0:
                threat = ThreatClass.POACHING_NETWORK.value
            if sig.rectangular_clearing:
                threat = ThreatClass.LAND_GRAB.value

            referred = []
            if sig.severity >= 9.0:
                referred = ["DCI_KENYA", "KFS_ENFORCEMENT", "INTERPOL_WILDLIFE",
                            "CARBON_REGISTRY_VERRA", "SATELLITE_EVIDENCE_UNIT"]
            elif sig.severity >= 6.0:
                referred = ["KFS_ENFORCEMENT", "CARBON_REGISTRY_VERRA"]

            dossier_ref = f"BG-SIG-{sig.parcel_id}"

            block = self._mint_block(
                block_type          = "VIOLATION",
                threat_class        = threat,
                entity              = sig.entity_name,
                region              = sig.region,
                parcel_id           = sig.parcel_id,
                summary             = (
                    f"{sig.signal_type}: NDVI claimed {sig.ndvi_claimed} "
                    f"vs satellite actual {sig.ndvi_actual} (delta {sig.ndvi_delta:+.2f}). "
                    f"Clearing {sig.clearing_rate_ha_per_month:.1f} ha/month. "
                    f"Night activity: {'YES' if sig.night_activity_detected else 'NO'}. "
                    f"Gunshot events: {sig.acoustic_gunshot_events}. "
                    f"Rectangular pattern: {'YES — commercial signature' if sig.rectangular_clearing else 'NO'}."
                ),
                contradiction_score = sig.severity,
                evidence_grade      = EvidenceGrade.CONFIRMED.value if sig.severity >= 8
                                      else EvidenceGrade.PROBABLE.value,
                carbon_at_risk      = int(sig.clearing_rate_ha_per_month * 12 * 150),
                land_ha             = 0,
                dossier_ref         = dossier_ref,
                linked              = linked_blocks,
                referred_to         = referred,
            )

            print(f"  [SIGNAL] {sig.entity_name[:40]:40} NDVI Δ{sig.ndvi_delta:+.2f} "
                  f"clearing={sig.clearing_rate_ha_per_month:.0f}ha/mo "
                  f"severity={sig.severity} block=#{block.block_index}")
            results.append(sig)

        return results

    # ── Layer 3: Actor Network Graph ───────────────────────────────────

    def build_actor_network(self) -> list[ActorLink]:
        print("\n[BIOGUARD-L3] Actor Network Graph — mapping connections...")
        results = []

        for raw in ACTOR_LINKS:
            link = ActorLink(**raw)
            self.network.append(link)

            # Find blocks for both actors
            linked_blocks = [b.block_index for b in self.blocks
                             if b.entity in (link.actor_a, link.actor_b)]

            block = self._mint_block(
                block_type          = "NETWORK",
                threat_class        = ThreatClass.MONEY_LAUNDERING.value
                                      if link.link_type == "FINANCIAL_FLOW"
                                      else ThreatClass.SHELL_CONSERVANCY.value,
                entity              = f"{link.actor_a} ↔ {link.actor_b}",
                region              = "Network",
                parcel_id           = f"NET-{link.link_type}",
                summary             = (
                    f"LINK TYPE: {link.link_type}. "
                    f"Strength: {link.strength:.0%}. "
                    f"Evidence: {link.evidence}."
                ),
                contradiction_score = link.strength * 10,
                evidence_grade      = EvidenceGrade.CONFIRMED.value
                                      if link.strength >= 0.9
                                      else EvidenceGrade.PROBABLE.value,
                carbon_at_risk      = 0,
                land_ha             = 0,
                dossier_ref         = f"BG-NET-{link.actor_a[:8].replace(' ','')}",
                linked              = linked_blocks,
                referred_to         = ["DCI_KENYA", "FINANCIAL_INTELLIGENCE_UNIT",
                                       "INTERPOL_FINANCIAL_CRIMES"],
            )

            print(f"  [LINK] {link.link_type:20} {link.actor_a[:22]:22} ↔ "
                  f"{link.actor_b[:22]:22} strength={link.strength:.0%} "
                  f"block=#{block.block_index}")
            results.append(link)

        return results

    # ── Full pipeline ──────────────────────────────────────────────────

    def run(self) -> dict:
        print("=" * 72)
        print("  BIOGUARD INTELLIGENCE SCANNER — EAST AFRICA CONSERVATION FRAUD")
        print("=" * 72)

        self.pierce_corporate_veil()
        self.run_contradiction_engine()
        self.build_actor_network()

        # Summary
        confirmed  = sum(1 for b in self.blocks if b.evidence_grade == "CONFIRMED")
        probable   = sum(1 for b in self.blocks if b.evidence_grade == "PROBABLE")
        total_fake_credits = sum(b.carbon_credits_at_risk for b in self.blocks)
        apex_nodes = [e for e in self.entities
                      if len(e.linked_entities) >= 3
                      and e.evidence_grade != EvidenceGrade.CLEARED]

        print("\n" + "=" * 72)
        print(f"  SCAN COMPLETE — {len(self.blocks)} blocks minted")
        print(f"  Confirmed violations : {confirmed}")
        print(f"  Probable violations  : {probable}")
        print(f"  Fraudulent credits   : {total_fake_credits:,} tCO₂")
        print(f"  Apex network nodes   : {len(apex_nodes)}")
        print(f"  Referrals issued     : DCI Kenya, KFS, INTERPOL, Carbon Registries")
        print("=" * 72)

        report = {
            "scan_timestamp"     : self._ts(),
            "total_blocks"       : len(self.blocks),
            "confirmed_violations": confirmed,
            "probable_violations" : probable,
            "fraudulent_credits" : total_fake_credits,
            "apex_nodes"         : [e.name for e in apex_nodes],
            "entities_scanned"   : len(self.entities),
            "network_links"      : len(self.network),
            "blocks"             : [asdict(b) for b in self.blocks],
            "dossiers"           : self.dossiers,
            "actor_network"      : [asdict(l) for l in self.network],
            "behavioral_signals" : [asdict(s) for s in self.signals],
        }

        return report


def run_bioguard(output_dir: str = "reports", chain_start: int = 109) -> dict:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    scanner = BioGuardScanner(chain_start_index=chain_start)
    report  = scanner.run()

    out = Path(output_dir)
    (out / "bioguard_report.json").write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8"
    )
    print(f"\n[BIOGUARD] Report saved → {out / 'bioguard_report.json'}")
    return report


if __name__ == "__main__":
    run_bioguard()
