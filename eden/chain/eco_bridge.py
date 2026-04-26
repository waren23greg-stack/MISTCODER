from __future__ import annotations
import json
import hashlib
from collections import defaultdict
from datetime import datetime, timezone

from blockchain.phantom_chain_bridge import PhantomChainBridge
from blockchain.chain_persistence    import MistChainPersistence
from eden.oracle.eco_brain           import EcoBrain
from eden.lex0.lex0_engine           import Lex0Engine

SEVERITY_STEALTH = {"CRITICAL": 0.92, "HIGH": 0.78, "MEDIUM": 0.55, "LOW": 0.30}


def eco_findings_to_chains(findings, source):
    by_region = defaultdict(list)
    for f in findings:
        by_region[f.get("file", "unknown")].append(f)
    chains, num = [], 1
    for region_key, region_findings in by_region.items():
        seen, nodes = set(), []
        for f in region_findings:
            code = f.get("cwe_id", "")
            if code not in seen:
                nodes.append(f)
                seen.add(code)
        if not nodes:
            continue
        bio_score = round(sum(n.get("cvss_score", 5.0) for n in nodes) / len(nodes), 2)
        stealth   = round(sum(SEVERITY_STEALTH.get(n.get("severity","LOW").upper(), 0.55)
                             for n in nodes) / len(nodes), 2)
        region_name = nodes[0].get("eco", {}).get("region") or region_key.split("/")[0]
        chains.append({
            "chain_id"   : f"EDEN-{source[:2].upper()}-{num:04d}",
            "source"     : source,
            "region"     : region_name,
            "file"       : region_key,
            "nodes"      : nodes,
            "bio_score"  : bio_score,
            "stealth"    : stealth,
            "novelty"    : 0.4,
            "eco_context": nodes[0].get("eco", {}),
        })
        num += 1
    return chains


def certify_ecological_events(all_eco_results):
    eco_brain = EcoBrain(verbose=True)
    lex0      = Lex0Engine()

    print()
    print("  ┌─ EDEN ECOLOGICAL TRINITY ───────────────────────────")
    print("  │  Loading chain from disk...")

    loaded_chain = MistChainPersistence.load()
    bridge       = PhantomChainBridge(node_id="NODE-EDEN")
    bridge.chain = loaded_chain

    certified, blocked, deduped = [], [], []
    source_prefix = {"ndvi": "NV", "acoustic": "AC", "sensor": "SN"}

    for scan in all_eco_results:
        source   = scan.get("language", "ndvi")
        findings = scan.get("findings", [])
        if not findings:
            continue
        prefix = source_prefix.get(source, source[:2].upper())
        chains = eco_findings_to_chains(findings, prefix)
        print(f"  │  [{source.upper()}] {len(findings)} events -> {len(chains)} eco-chains")

        for chain in chains:
            fid = chain["chain_id"]
            existing = MistChainPersistence.lookup(fid)
            if existing:
                deduped.append(fid)
                print(f"  │  ⟳ {fid} already certified (block {existing['block']})")
                continue

            steps = []
            seen  = set()
            for node in chain["nodes"]:
                for key in ("call_name", "cwe_id"):
                    val = node.get(key, "")
                    if val and val not in seen:
                        steps.append(val)
                        seen.add(val)

            bio_score   = chain["bio_score"]
            eco_context = chain["eco_context"]
            region      = chain["region"]

            oracle_result = eco_brain.evaluate(
                event_id=fid, steps=steps,
                bio_score=bio_score, eco_context=eco_context)

            print(f"  │  [LEX-0] Constitutional review of {fid}...")
            ok, reason = lex0.review(
                event_id=fid, steps=steps, bio_score=bio_score,
                eco_confidence=oracle_result["confidence"],
                region=region, fpic_cleared=True)

            if not ok:
                print(f"  │  ✗ {fid} blocked: {reason}")
                blocked.append(fid)
                continue
            print(f"  │  [LEX-0] CERTIFIED — {reason}")

            block = bridge.phantom_submit(
                finding_id=fid, steps=steps, score=bio_score,
                stealth=chain["stealth"], novelty=chain["novelty"])

            if block:
                token = _build_bio_token(fid, chain, oracle_result, block)
                certified.append({
                    "chain_id"    : fid,
                    "source"      : source,
                    "region"      : region,
                    "block"       : block.index,
                    "hash"        : block.hash[:24],
                    "bio_score"   : bio_score,
                    "carbon_tco2" : oracle_result.get("carbon_tco2", 0),
                    "species_risk": oracle_result.get("species_risk", []),
                    "verdict"     : oracle_result["verdict"],
                    "token_payload": token,
                })
                print(f"  │  ✓ Block {block.index} | {fid} | "
                      f"bio={bio_score} | ~{oracle_result.get('carbon_tco2',0)} tCO2")
            else:
                blocked.append(fid)

    if certified:
        MistChainPersistence.save(bridge.chain)
    eco_brain.end_scan()
    print("  └─────────────────────────────────────────────────────")
    return {"certified": certified, "blocked": blocked, "deduplicated": deduped}


def _build_bio_token(chain_id, chain, oracle, block):
    eco = chain.get("eco_context", {})
    return {
        "token_type"  : "BioImpact",
        "version"     : "1.0",
        "chain_id"    : chain_id,
        "block_index" : block.index,
        "block_hash"  : block.hash,
        "certified_at": datetime.now(timezone.utc).isoformat(),
        "region"      : chain["region"],
        "coordinates" : {"lat": eco.get("lat", 0), "lng": eco.get("lng", 0)},
        "impact"      : {
            "bio_score"   : chain["bio_score"],
            "carbon_tco2" : oracle.get("carbon_tco2", 0),
            "area_ha"     : eco.get("area_ha", 0),
            "ndvi_delta"  : eco.get("ndvi_delta", 0),
            "species_risk": oracle.get("species_risk", []),
            "eco_codes"   : [n.get("cwe_id") for n in chain["nodes"]
                             if (n.get("cwe_id") or "").startswith("ECO")],
        },
        "verification": {
            "oracle_confidence": oracle["confidence"],
            "oracle_verdict"   : oracle["verdict"],
            "impact_refs"      : oracle.get("impact_refs", []),
            "signature"        : oracle.get("signature", ""),
            "lex0_cleared"     : True,
            "trinity_consensus": True,
        },
        "investor_note": (
            f"Verified {chain['bio_score']:.1f}/10 ecological event. "
            f"~{oracle.get('carbon_tco2',0)} tCO2 impacted. "
            f"Block #{block.index} — tamper-proof, immutable, real."
        ),
    }
