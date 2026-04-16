"""
MISTCODER MOD-03 -- CLI runner
Wraps reasoning_core with correct sys.path so relative imports resolve.
Usage: python modules/reasoning/run_reasoning.py <ir_json> <findings_json> [--export out.json]
"""
import sys
import os

# ensure the src directory is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from reasoning_core import ReasoningEngine
import json

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python run_reasoning.py <ir_json> <findings_json> [--export out.json]")
        sys.exit(1)

    ir_path       = sys.argv[1]
    findings_path = sys.argv[2]
    export_path   = sys.argv[4] if len(sys.argv) >= 5 and sys.argv[3] == "--export" else None

    with open(ir_path,       "r") as f: ir       = json.load(f)
    with open(findings_path, "r") as f: findings = json.load(f)

    finding_list = findings.get("findings", [])

    engine = ReasoningEngine()
    result = engine.analyze(ir, finding_list)
    engine.print_reasoning(result)

    if export_path:
        engine.export(result, export_path)
