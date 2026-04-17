"""
MISTCODER MOD-03 -- CLI runner
Usage: python modules/reasoning/run_reasoning.py <ir_json> <findings_json> [--export out.json]
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from reasoning_core import ReasoningCore, ReasoningConfig

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python run_reasoning.py <ir_json> <findings_json> [--export out.json]")
        sys.exit(1)

    ir_path       = sys.argv[1]
    findings_path = sys.argv[2]
    export_path   = sys.argv[4] if len(sys.argv) >= 5 and sys.argv[3] == "--export" else None

    with open(ir_path,       "r", encoding="utf-8") as f: ir       = json.load(f)
    with open(findings_path, "r", encoding="utf-8") as f: findings_doc = json.load(f)

    finding_list = findings_doc.get("findings", [])

    # Convert MOD-02 finding dicts to MOD-03 expected format
    converted = []
    for f in finding_list:
        converted.append({
            "id":         f.get("finding_id", f.get("id", "unknown")),
            "kind":       f.get("call_name",  f.get("kind", "UNKNOWN")).upper(),
            "severity":   f.get("severity",   "MEDIUM"),
            "file_path":  f.get("file",       f.get("file_path", "unknown")),
            "line_start": f.get("line",       f.get("line_start", 0)),
            "line_end":   f.get("line",       f.get("line_end",   0)),
            "confidence": f.get("confidence", 1.0),
            "cwe_ids":    [f.get("cwe_id", "CWE-0")] if f.get("cwe_id") else [],
            "metadata":   {},
        })

    config = ReasoningConfig(target_name=os.path.basename(ir_path))
    core   = ReasoningCore(config)
    result = core.reason(converted)    # <-- correct method name
    result.print_summary()

    if export_path:
        os.makedirs(os.path.dirname(export_path) or ".", exist_ok=True)
        with open(export_path, "w", encoding="utf-8") as f:
            f.write(result.to_json())
        print(f"[MOD-03] Report exported to {export_path}")
