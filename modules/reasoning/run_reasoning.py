"""
MISTCODER MOD-03 -- CLI runner
Usage: python modules/reasoning/run_reasoning.py <ir_json> <findings_json> [--export out.json]
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from reasoning_core import ReasoningCore, ReasoningConfig

# Maps MOD-02 call_name → MOD-03 chain-pattern token
KIND_MAP = {
    "eval":           "RCE_INJECTION",
    "exec":           "RCE_COMMAND_EXEC",
    "execsync":       "RCE_COMMAND_EXEC",
    "function":       "RCE_INJECTION",
    "os.system":      "RCE_COMMAND_EXEC",
    "os.popen":       "RCE_COMMAND_EXEC",
    "subprocess":     "RCE_COMMAND_EXEC",
    "document.write": "XSS_REFLECTED",
    "innerhtml":      "XSS_REFLECTED",
    "pickle.loads":   "DESERIALIZATION_UNSAFE",
    "yaml.load":      "DESERIALIZATION_UNSAFE",
    "__import__":     "RCE_INJECTION",
    "compile":        "RCE_INJECTION",
    "open":           "PATH_TRAVERSAL",
    "settimeout":     "RCE_INJECTION",
    "setinterval":    "RCE_INJECTION",
}

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python run_reasoning.py <ir_json> <findings_json> [--export out.json]")
        sys.exit(1)

    ir_path       = sys.argv[1]
    findings_path = sys.argv[2]
    export_path   = sys.argv[4] if len(sys.argv) >= 5 and sys.argv[3] == "--export" else None

    with open(ir_path,       "r", encoding="utf-8") as f: ir          = json.load(f)
    with open(findings_path, "r", encoding="utf-8") as f: findings_doc = json.load(f)

    finding_list = findings_doc.get("findings", [])

    converted = []
    for i, f in enumerate(finding_list):
        raw_name = f.get("call_name", f.get("kind", "UNKNOWN")).lower()
        kind     = KIND_MAP.get(raw_name, raw_name.upper())
        converted.append({
            "id":         f.get("finding_id", f"f-{i+1:03d}"),
            "kind":       kind,
            "severity":   f.get("severity",   "MEDIUM"),
            "file_path":  f.get("file",       f.get("file_path", "unknown")),
            "line_start": f.get("line",       f.get("line_start", 0)),
            "line_end":   f.get("line",       f.get("line_end",   0)),
            "confidence": min(1.0, f.get("cvss_score", 5.0) / 10.0),
            "cwe_ids":    [f.get("cwe_id", "CWE-0")] if f.get("cwe_id") else [],
            "metadata":   {"original_call": raw_name, "taint_confirmed": bool(f.get("taint_path"))},
        })

    config = ReasoningConfig(target_name=os.path.basename(ir_path))
    core   = ReasoningCore(config)
    result = core.reason(converted)
    result.print_summary()

    if export_path:
        os.makedirs(os.path.dirname(export_path) or ".", exist_ok=True)
        with open(export_path, "w", encoding="utf-8") as f:
            f.write(result.to_json())
        print(f"[MOD-03] Report exported to {export_path}")
