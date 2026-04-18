"""
MISTCODER -- End-to-End Demo
"""

import os, sys, json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

sys.path.insert(0, os.path.join(ROOT, "modules", "ingestion",  "src"))
sys.path.insert(0, os.path.join(ROOT, "modules", "analysis",   "src"))
sys.path.insert(0, os.path.join(ROOT, "modules", "reporting",  "src"))
sys.path.insert(0, os.path.join(ROOT, "modules", "scoring",    "src"))

from parser           import IngestionEngine
from analysis_engine  import AnalysisEngine
from report_generator import ReportGenerator
from cvss_scorer      import CVSSScorer

TARGET = os.path.join(ROOT, "sandbox", "vulnerable_app", "app.py")
OUTDIR = os.path.join(ROOT, "reports", "demo")
os.makedirs(OUTDIR, exist_ok=True)

SEP  = "=" * 60
SEP2 = "-" * 60

def run():
    print()
    print(SEP)
    print("  MISTCODER -- End-to-End Demo Scan")
    print(SEP)
    print(f"  Target  : {TARGET}")
    print(f"  Output  : {OUTDIR}")
    print(SEP2)

    # MOD-01
    print()
    print("[MOD-01] Ingesting target...")
    ir = IngestionEngine().ingest_file(TARGET)
    m  = ir.get("metadata", {})
    print(f"  Language        : {ir['language']}")
    print(f"  Nodes extracted : {m.get('node_count', 0)}")
    print(f"  Edges extracted : {m.get('edge_count', 0)}")
    print(f"  Dangerous calls : {m.get('dangerous_calls', 0)}")
    print(f"  Secret flags    : {m.get('secret_flags', 0)}")
    print(f"  SHA-256         : {ir.get('hash','')[:24]}...")
    with open(os.path.join(OUTDIR, "ir.json"), "w") as f:
        json.dump(ir, f, indent=2)

    # MOD-02
    print()
    print("[MOD-02] Running static analysis...")
    report   = AnalysisEngine().analyze(ir)
    am       = report.get("metadata", {})
    sev      = am.get("severity_summary", {})
    findings = report.get("findings", [])
    print(f"  Taint flows     : {am.get('taint_flow_count', 0)}")
    print(f"  CFG functions   : {am.get('cfg_function_count', 0)}")
    print(f"  Findings        : {am.get('finding_count', 0)}")
    print(f"  Critical        : {sev.get('critical', 0)}")
    print(f"  High            : {sev.get('high', 0)}")
    print(f"  Medium          : {sev.get('medium', 0)}")
    print()
    print(SEP2)
    print("  FINDINGS DISCOVERED:")
    print(SEP2)
    ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for f in sorted(findings, key=lambda x: ORDER.get(x.get("severity","low"), 3)):
        print(f"  [{f.get('severity','').upper():8s}] {f['id']}  {f['category']}")
        print(f"             {f.get('description','')[:80]}")
    with open(os.path.join(OUTDIR, "analysis.json"), "w") as f:
        json.dump(report, f, indent=2)

    # MOD-03 -- build a lightweight threat model from MOD-02 output
    # (avoids import conflicts with on-disk reasoning_core version)
    print()
    print("[MOD-03] Building threat model from findings...")
    from itertools import combinations

    CHAIN_MATRIX = {
        ("SECRET_EXPOSURE", "DANGEROUS_CALL"): "critical",
        ("DANGEROUS_CALL",  "SECRET_EXPOSURE"): "critical",
        ("TAINT_FLOW",      "DANGEROUS_CALL"):  "high",
        ("DANGEROUS_CALL",  "TAINT_FLOW"):      "high",
        ("SECRET_EXPOSURE", "TAINT_FLOW"):      "high",
    }

    chains = []
    cat_map = {f["id"]: f.get("category","") for f in findings}
    for (id_a, cat_a), (id_b, cat_b) in combinations(cat_map.items(), 2):
        combined = CHAIN_MATRIX.get((cat_a, cat_b)) or CHAIN_MATRIX.get((cat_b, cat_a))
        if combined:
            chains.append({
                "id":                f"CH-{len(chains)+1:04d}",
                "links":             [id_a, id_b],
                "combined_severity": combined,
                "narrative": (
                    f"Vulnerability chain detected. '{cat_a}' combined with "
                    f"'{cat_b}' produces a {combined.upper()} severity breach "
                    f"path. Neither finding is critical in isolation -- "
                    f"their combination enables a complete exploitation scenario."
                ),
                "confidence": 0.85
            })

    overall = "low"
    if any(c["combined_severity"] == "critical" for c in chains):
        overall = "critical"
    elif any(c["combined_severity"] == "high" for c in chains):
        overall = "high"
    elif findings:
        overall = "medium"

    reasoning_result = {
        "file":      TARGET,
        "language":  "python",
        "attack_graph": {"nodes": [], "edges": []},
        "attack_paths": [],
        "chains":    chains,
        "anomalies": [],
        "threat_model": {
            "overall_risk":      overall,
            "attack_path_count": 0,
            "chain_count":       len(chains),
            "anomaly_count":     0,
            "critical_paths":    0,
            "high_paths":        0,
            "critical_chains":   sum(1 for c in chains if c["combined_severity"] == "critical"),
        },
        "metadata": {
            "graph_node_count":  len(ir.get("nodes", [])),
            "graph_edge_count":  len(ir.get("edges", [])),
            "attack_path_count": 0,
            "chain_count":       len(chains),
            "anomaly_count":     0,
            "overall_risk":      overall,
            "reasoner":          "ReasoningCore v0.1.0 (demo mode)",
            "reasoned_at":       __import__("datetime").datetime.utcnow().isoformat() + "Z"
        }
    }

    print(f"  Chains detected : {len(chains)}")
    print()
    print(SEP)
    print(f"  OVERALL RISK    : {overall.upper()}")
    print(SEP)
    if chains:
        print()
        print("  VULNERABILITY CHAINS:")
        for ch in chains[:6]:
            print(f"  [{ch['combined_severity'].upper():8s}] {ch['id']}  conf={ch['confidence']:.0%}")
            print(f"             {ch['narrative'][:90]}")

    with open(os.path.join(OUTDIR, "reasoning.json"), "w") as f:
        json.dump(reasoning_result, f, indent=2)

    # CVSS Scoring
    print()
    print("[SCORER] Computing CVSS 3.1 risk scores...")
    scorer     = CVSSScorer()
    score_data = scorer.score(findings, chains, [])
    agg        = score_data.get("aggregate", {})
    print(f"  Aggregate score : {agg.get('score', 0)} / 10.0")
    print(f"  Risk label      : {agg.get('label', '')}")
    print(f"  Risk vector     : {score_data.get('risk_vector', '')}")
    print()
    print(f"  {score_data.get('risk_label','')[:80]}")
    with open(os.path.join(OUTDIR, "scores.json"), "w") as f:
        json.dump(score_data, f, indent=2)

    # HTML Report
    print()
    print("[MOD-06] Generating HTML report...")
    gen       = ReportGenerator(output_dir=os.path.join(ROOT, "reports"))
    html_path = gen.generate_report(
        ir               = ir,
        analysis_report  = report,
        reasoning_result = reasoning_result,
        filename         = "MISTCODER_VulnFlask_demo.html",
        target_label     = "VulnFlask Demo Application (sandbox/vulnerable_app/app.py)",
        analyst_name     = "MISTCODER Autonomous Pipeline v0.1.0",
        classification   = "DEMO -- NOT FOR DISTRIBUTION",
    )

    print()
    print(SEP)
    print("  SCAN COMPLETE")
    print(SEP)
    print(f"  Findings   : {len(findings)}")
    print(f"  Chains     : {len(chains)}")
    print(f"  Risk score : {agg.get('score',0)} / 10.0  [{agg.get('label','')}]")
    print(f"  Report     : {html_path}")
    print(f"  JSON data  : {OUTDIR}")
    print(SEP)
    print()

if __name__ == "__main__":
    run()
