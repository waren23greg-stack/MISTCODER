"""
bioguard_cli.py — BioGuard Command Line Interface
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from bioguard.scanner import run_bioguard
from bioguard.dossier import generate_dossiers


def main():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║          B I O G U A R D   I N T E L L I G E N C E             ║
║      Conservation Fraud Detection Platform — East Africa         ║
╚══════════════════════════════════════════════════════════════════╝
    """)

    # Run scanner
    report = run_bioguard(output_dir="reports", chain_start=109)

    # Generate dossiers
    print("\n[BIOGUARD] Generating enforcement dossiers...")
    dossiers = generate_dossiers(
        report_path="reports/bioguard_report.json",
        output_dir="reports/dossiers"
    )

    # Print apex network
    print("\n[BIOGUARD] APEX NETWORK NODES (highest risk):")
    for node in report.get("apex_nodes", []):
        print(f"  ◉ {node}")

    print(f"""
┌─────────────────────────────────────────────────────────────────┐
│  SCAN SUMMARY                                                   │
│  Blocks minted     : {report['total_blocks']:>6}                                  │
│  Confirmed         : {report['confirmed_violations']:>6}                                  │
│  Probable          : {report['probable_violations']:>6}                                  │
│  Fraudulent credits: {report['fraudulent_credits']:>6,} tCO₂                          │
│  Dossiers issued   : {len(dossiers):>6}                                  │
│  Referral agencies : DCI · KFS · INTERPOL · Verra · UNFCCC     │
└─────────────────────────────────────────────────────────────────┘
""")


if __name__ == "__main__":
    main()
