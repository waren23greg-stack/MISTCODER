"""
MISTCODER -- End-to-End Demo
Scans the deliberately vulnerable Flask app and produces a full report.

Usage:
    python sandbox/run_demo.py

Output:
    Terminal  -- live findings as discovered
    HTML      -- reports/MISTCODER_VulnFlask_demo.html
    JSON      -- reports/demo/ir.json
               reports/demo/analysis.json
               reports/demo/reasoning.json
"""

import os
import sys
import json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for mod in ["ingestion/src", "analysis/src", "reasoning/src",
            "reporting/src", "scoring/src"]:
    sys.path.insert(0, os.path.join(ROOT, "modules", mod))

from parser          import PythonParser, IngestionEngine
from analysis_engine import AnalysisEngine
from reasoning_core  import ReasoningCore
from report_generator import ReportGenerator
from cvss_scorer      import CVSSScorer


TARGET = os.path.join(ROOT, "sandbox", "vulnerable_app", "app.py")
OUTDIR = os.path.join(ROOT, "reports", "demo")
os.makedirs(OUTDIR, exist_ok=True)


def divider(char="-", width=60):
    print(char * width)

def header(text):
    divider("=")
    print(f"  {text}")
    divider("=")


def run():
    print()
    header("MISTCODER -- End-to-End Demo Scan")
    print(f"  Target  : {TARGET}")
    print(f"  Output  : {OUTDIR}")
    divider()

    # -----------------------------------------------------------------------
    # Stage 1 -- MOD-01 Ingestion
    # -----------------------------------------------------------------------
    print()
    print("[MOD-01] Ingesting target...")
    engine = IngestionEngine()
    ir     = engine.ingest_file(TARGET)
    m      = ir.get("metadata", {})
    print(f"  Language        : {ir['language']}")
    print(f"  Nodes extracted : {m.get('node_count', 0)}")
    print(f"  Edges extracted : {m.get('edge_count', 0)}")
    print(f"  Dangerous calls : {m.get('dangerous_calls', 0)}")
    print(f"  Secret flags    : {m.get('secret_flags', 0)}")
    print(f"  SHA-256         : {ir.get('hash', '')[:24]}...")

    with open(os.path.join(OUTDIR, "ir.json"), "w") as f:
        json.dump(ir, f, indent=2)

    # -----------------------------------------------------------------------
    # Stage 2 -- MOD-02 Static Analysis
    # -----------------------------------------------------------------------
    print()
    print("[MOD-02] Running static analysis...")
    analyser = AnalysisEngine()
    report   = analyser.analyze(ir)
    am       = report.get("metadata", {})
    print(f"  Taint flows     : {am.get('taint_flow_count', 0)}")
    print(f"  CFG functions   : {am.get('cfg_function_count', 0)}")
    print(f"  Findings        : {am.get('finding_count', 0)}")
    sev = am.get("severity_summary", {})
    print(f"  Critical        : {sev.get('critical', 0)}")
    print(f"  High            : {sev.get('high', 0)}")
    print(f"  Medium          : {sev.get('medium', 0)}")

    print()
    divider()
    print("  FINDINGS DISCOVERED:")
    divider()
    findings = report.get("findings", [])
    for f in sorted(findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x.get("severity","low"),3)):
        sev_label = f.get("severity","").upper()
        print(f"  [{sev_label:8s}] {f['id']}  {f['category']}")
        print(f"             {f['description'][:80]}")

    with open(os.path.join(OUTDIR, "analysis.json"), "w") as f:
        json.dump(report, f, indent=2)

    # -----------------------------------------------------------------------
    # Stage 3 -- MOD-03 Reasoning Core
    # -----------------------------------------------------------------------
    print()
    print("[MOD-03] Reasoning about attack surface...")
    core    = ReasoningCore()
    result  = core.reason(ir, report)
    rm      = result.get("metadata", {})
    tm      = result.get("threat_model", {})

    print(f"  Graph nodes     : {rm.get('graph_node_count', 0)}")
    print(f"  Graph edges     : {rm.get('graph_edge_count', 0)}")
    print(f"  Attack paths    : {rm.get('attack_path_count', 0)}")
    print(f"  Vuln chains     : {rm.get('chain_count', 0)}")
    print(f"  Anomalies       : {rm.get('anomaly_count', 0)}")
    print()
    divider()
    print(f"  OVERALL RISK    : {tm.get('overall_risk','').upper()}")
    divider()

    chains = result.get("chains", [])
    if chains:
        print()
        print("  VULNERABILITY CHAINS:")
        for ch in chains[:5]:
            print(f"  [{ch['combined_severity'].upper():8s}] {ch['id']}  "
                  f"conf={ch['confidence']:.0%}")
            print(f"             {ch['narrative'][:90]}")

    anomalies = result.get("anomalies", [])
    if anomalies:
        print()
        print("  BEHAVIORAL ANOMALIES (beyond CVE signatures):")
        for an in anomalies[:4]:
            print(f"  [{an['severity'].upper():8s}] {an['id']}  "
                  f"fn={an['function_name']}")
            print(f"             {an['violation'][:90]}")

    with open(os.path.join(OUTDIR, "reasoning.json"), "w") as f:
        json.dump(result, f, indent=2)

    # -----------------------------------------------------------------------
    # Stage 4 -- CVSS Scoring
    # -----------------------------------------------------------------------
    print()
    print("[SCORER] Computing CVSS 3.1 risk scores...")
    scorer     = CVSSScorer()
    score_data = scorer.score(findings, chains,
                              result.get("attack_paths", []))
    agg        = score_data.get("aggregate", {})
    print(f"  Aggregate score : {agg.get('score', 0)} / 10.0")
    print(f"  Risk label      : {agg.get('label', '')}")
    print(f"  Risk vector     : {score_data.get('risk_vector', '')}")
    print()
    print(f"  {score_data.get('risk_label','')[:80]}")

    with open(os.path.join(OUTDIR, "scores.json"), "w") as f:
        json.dump(score_data, f, indent=2)

    # -----------------------------------------------------------------------
    # Stage 5 -- HTML Report
    # -----------------------------------------------------------------------
    print()
    print("[MOD-06] Generating HTML report...")
    gen      = ReportGenerator(output_dir=os.path.join(ROOT, "reports"))
    html_path = gen.generate_report(
        ir               = ir,
        analysis_report  = report,
        reasoning_result = result,
        filename         = "MISTCODER_VulnFlask_demo.html",
        target_label     = "VulnFlask Demo Application (sandbox/vulnerable_app/app.py)",
        analyst_name     = "MISTCODER Autonomous Pipeline v0.1.0",
        classification   = "DEMO -- NOT FOR DISTRIBUTION",
    )

    print()
    divider("=")
    print("  SCAN COMPLETE")
    divider("=")
    print(f"  Findings   : {len(findings)}")
    print(f"  Chains     : {len(chains)}")
    print(f"  Risk score : {agg.get('score', 0)} / 10.0  [{agg.get('label','')}]")
    print(f"  Report     : {html_path}")
    print(f"  JSON data  : {OUTDIR}/")
    divider("=")
    print()


if __name__ == "__main__":
    run()
