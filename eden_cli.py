from __future__ import annotations
import sys
import json
import time
import argparse
from pathlib import Path
from datetime import datetime, timezone

BANNER = """
  ███████╗██████╗ ███████╗███╗   ██╗
  ██╔════╝██╔══██╗██╔════╝████╗  ██║
  █████╗  ██║  ██║█████╗  ██╔██╗ ██║
  ██╔══╝  ██║  ██║██╔══╝  ██║╚██╗██║
  ███████╗██████╔╝███████╗██║ ╚████║
  ╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═══╝
  Ecological Defense & Economic Network
  Powered by MISTCODER Trinity Blockchain
"""

PILOT_REGIONS = [
    {"lat": -0.315, "lng": 35.634, "region_name": "Mau Forest",
     "biome": "tropical_forest", "radius_km": 15.0},
    {"lat": -1.292, "lng": 36.821, "region_name": "Nairobi Eastlands",
     "biome": "woodland",        "radius_km": 8.0},
    {"lat": -0.091, "lng": 34.767, "region_name": "Rift Valley",
     "biome": "grassland",       "radius_km": 20.0},
]

ACOUSTIC_NODES = [
    {"node_id": "BIOGUARD-MAU-01", "lat": -0.315, "lng": 35.634, "region": "Mau Forest"},
    {"node_id": "BIOGUARD-MAU-02", "lat": -0.298, "lng": 35.651, "region": "Mau Forest"},
    {"node_id": "BIOGUARD-RFT-01", "lat": -1.310, "lng": 36.798, "region": "Rift Valley"},
]


def cmd_scan(args):
    from eden.sensing.ndvi_scanner     import NDVIScanner
    from eden.sensing.acoustic_scanner import AcousticScanner
    from eden.chain.eco_bridge         import certify_ecological_events

    print(BANNER)
    t0           = time.time()
    scan_results = []
    regions      = PILOT_REGIONS if args.all_pilots else [
        {"lat": args.lat, "lng": args.lng, "region_name": args.region,
         "biome": args.biome, "radius_km": args.radius}]
    nodes        = ACOUSTIC_NODES if args.all_pilots else []

    print(f"  Regions  : {[r['region_name'] for r in regions]}")
    print(f"  Pipeline : Scan -> EcoOracle -> Lex-0 -> Trinity -> Chain")
    print()

    ndvi_result = NDVIScanner().scan_regions(regions)
    scan_results.append(ndvi_result)

    ac = AcousticScanner()
    ac_result = {"language": "acoustic", "scanner": "Acoustic Scanner",
                 "files": len(nodes), "findings": [],
                 "summary": {"critical":0,"high":0,"medium":0,"low":0,"total":0}}
    for node in nodes:
        r = ac.scan_node(**node)
        ac_result["findings"].extend(r["findings"])
        for k in ("critical","high","medium","low","total"):
            ac_result["summary"][k] += r["summary"].get(k, 0)
    if ac_result["findings"]:
        scan_results.append(ac_result)

    trinity = certify_ecological_events(scan_results)
    elapsed = round(time.time() - t0, 2)

    total_events = sum(len(s.get("findings",[])) for s in scan_results)
    total_carbon = sum(c.get("carbon_tco2",0) for c in trinity["certified"])
    total_area   = sum(c.get("token_payload",{}).get("impact",{}).get("area_ha",0)
                       for c in trinity["certified"])

    print()
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║         EDEN × MISTCODER ECOLOGICAL REPORT          ║")
    print("  ╠══════════════════════════════════════════════════════╣")
    print(f"  ║  Scanned at  : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'):<37}║")
    print(f"  ║  Elapsed     : {str(elapsed)+'s':<37}║")
    print(f"  ║  Eco Events  : {str(total_events):<37}║")
    print("  ╠══════════════════════════════════════════════════════╣")
    print("  ║  TRINITY BLOCKCHAIN                                  ║")
    print(f"  ║    Certified : {str(len(trinity['certified'])):<37}║")
    print(f"  ║    Blocked   : {str(len(trinity['blocked'])):<37}║")
    print(f"  ║    Deduped   : {str(len(trinity['deduplicated'])):<37}║")
    print("  ╠══════════════════════════════════════════════════════╣")
    print("  ║  IMPACT SUMMARY                                      ║")
    print(f"  ║    Carbon at risk : {str(round(total_carbon,1))+' tCO2':<33}║")
    print(f"  ║    Area affected  : {str(round(total_area,1))+' ha':<33}║")
    print(f"  ║    BioTokens ready: {str(len(trinity['certified'])):<33}║")
    print("  ╠══════════════════════════════════════════════════════╣")
    print("  ║  CERTIFIED EVENTS                                    ║")
    for c in trinity["certified"][:6]:
        cid    = c["chain_id"].ljust(22)
        region = c["region"][:16].ljust(16)
        blk    = str(c["block"])
        print(f"  ║    {cid} {region} blk={blk:<6}           ║")
    print("  ╚══════════════════════════════════════════════════════╝")

    outdir = Path(args.outdir)
    outdir.mkdir(exist_ok=True)

    out = outdir / "eden_report.json"
    out.write_text(json.dumps({
        "scanned_at"      : datetime.now(timezone.utc).isoformat(),
        "elapsed_s"       : elapsed,
        "trinity"         : {"certified": len(trinity["certified"]),
                             "blocked": len(trinity["blocked"]),
                             "deduplicated": len(trinity["deduplicated"])},
        "certified_events": trinity["certified"],
    }, indent=2), encoding="utf-8")
    print(f"\n  [*] EDEN report saved -> {out}")

    tokens = [c["token_payload"] for c in trinity["certified"] if "token_payload" in c]
    tok_out = outdir / "bio_tokens.json"
    tok_out.write_text(json.dumps(tokens, indent=2), encoding="utf-8")
    print(f"  [*] BioImpact tokens -> {tok_out}  ({len(tokens)} tokens)")


def cmd_tokens(args):
    tok_file = Path(args.outdir) / "bio_tokens.json"
    if not tok_file.exists():
        print("No tokens. Run: python eden_cli.py scan --all-pilots")
        return
    tokens = json.loads(tok_file.read_text(encoding="utf-8"))
    print(f"\n  BioImpact Tokens — {len(tokens)} verified ecological events\n")
    for t in tokens:
        imp = t.get("impact", {})
        ver = t.get("verification", {})
        print(f"  * {t['chain_id']}  Block #{t['block_index']}")
        print(f"    Region  : {t['region']}")
        print(f"    Carbon  : ~{imp.get('carbon_tco2',0)} tCO2")
        print(f"    Area    : {imp.get('area_ha',0)} ha")
        print(f"    Oracle  : {ver.get('oracle_confidence',0)} {ver.get('oracle_verdict','')}")
        print(f"    Note    : {t.get('investor_note','')[:75]}")
        print()


def cmd_chain(args):
    from blockchain.chain_persistence import MistChainPersistence
    from datetime import datetime
    mc     = MistChainPersistence.load()
    blocks = getattr(mc, "chain", [])
    print(f"\n  EDEN x MISTCODER Chain — {len(blocks)} total blocks\n")
    print(f"  {'INDEX':<7} {'HASH':<28} {'TIMESTAMP'}")
    print(f"  {'─'*7} {'─'*28} {'─'*19}")
    for block in blocks[-15:]:
        idx = getattr(block, "index", "?")
        h   = getattr(block, "hash",  "")[:26]
        raw = getattr(block, "timestamp", 0)
        try:
            ts = datetime.utcfromtimestamp(float(raw)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            ts = str(raw)[:19]
        print(f"  {str(idx):<7} {h:<28} {ts}")
    print()


def main():
    parser = argparse.ArgumentParser(prog="eden",
        description="EDEN x MISTCODER — Ecological Intelligence on Blockchain")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("scan", help="Scan ecological regions")
    p.add_argument("--all-pilots", action="store_true")
    p.add_argument("--region",  default="Mau Forest")
    p.add_argument("--lat",     type=float, default=-0.315)
    p.add_argument("--lng",     type=float, default=35.634)
    p.add_argument("--biome",   default="tropical_forest")
    p.add_argument("--radius",  type=float, default=10.0)
    p.add_argument("--outdir",  default="reports")

    pt = sub.add_parser("tokens", help="Show BioImpact tokens")
    pt.add_argument("--outdir", default="reports")

    pc = sub.add_parser("chain", help="Show chain")
    pc.add_argument("--outdir", default="reports")

    args = parser.parse_args()
    if   args.command == "scan":   cmd_scan(args)
    elif args.command == "tokens": cmd_tokens(args)
    elif args.command == "chain":  cmd_chain(args)
    else:
        print(BANNER); parser.print_help()

if __name__ == "__main__":
    main()
