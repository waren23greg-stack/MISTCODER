"""
MISTCODER MOD-03 -- CLI runner
Usage: python modules/reasoning/run_reasoning.py <ir_json> <findings_json> [--export out.json]
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from reasoning_core import ReasoningCore, ReasoningConfig
import json

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python run_reasoning.py <ir_json> <findings_json> [--export out.json]")
        sys.exit(1)

    ir_path       = sys.argv[1]
    findings_path = sys.argv[2]
    export_path   = sys.argv[4] if len(sys.argv) >= 5 and sys.argv[3] == "--export" else None

    with open(ir_path,       "r", encoding="utf-8") as f: ir       = json.load(f)
    with open(findings_path, "r", encoding="utf-8") as f: findings = json.load(f)

    finding_list = findings.get("findings", [])

    config = ReasoningConfig()
    engine = ReasoningCore(config)
    result = engine.analyze(ir, finding_list)

    # Print summary
    print()
    print("=" * 70)
    print("  MISTCODER -- MOD-03 REASONING CORE REPORT")
    print(f"  File      : {ir.get('file', 'unknown')}")
    print(f"  Findings  : {len(finding_list)}")
    print("=" * 70)
    print(f"  Attack chains   : {len(getattr(result, 'attack_chains', []))}")
    print(f"  Risk score      : {getattr(result, 'aggregate_risk', 'n/a')}")
    print("=" * 70)

    if export_path:
        os.makedirs(os.path.dirname(export_path) or ".", exist_ok=True)
        # Convert result to dict if it has a method, else use vars
        if hasattr(result, 'to_dict'):
            out = result.to_dict()
        elif hasattr(result, '__dict__'):
            out = vars(result)
        else:
            out = str(result)
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, default=str)
        print(f"[MOD-03] Report exported to {export_path}")
