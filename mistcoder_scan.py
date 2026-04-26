"""
MISTCODER  |  Unified Scanner CLI
──────────────────────────────────────────────────────────────────────
Usage:
  python mistcoder_scan.py <target> [--export reports/out.json]

Target can be:
  • A local file path      sandbox/sample_target.py
  • A web URL              https://target.com
  • An API URL             https://api.service.com/v1
  • An AI service URL      https://api.openai.com
  • A local network URL    http://192.168.1.1/admin
──────────────────────────────────────────────────────────────────────
"""
import sys
import os
import re
import json

# Add module paths
BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, "modules", "ingestion", "src"))
sys.path.insert(0, os.path.join(BASE, "modules", "analysis",  "src"))
sys.path.insert(0, os.path.join(BASE, "modules", "reasoning", "src"))

def is_url(target):
    return target.startswith(("http://", "https://", "www.")) or \
           re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target)

def run_file_scan(target, export_base):
    from parser   import Parser
    from analyzer import AnalysisEngine

    print(f"\n[MISTCODER] File scan: {target}")
    parser = Parser()
    ir     = parser.parse(target)

    ir_path = os.path.join(export_base, "url_ir_file.json")
    os.makedirs(export_base, exist_ok=True)
    with open(ir_path, "w", encoding="utf-8") as f:
        json.dump(ir, f, indent=2)

    engine = AnalysisEngine()
    engine.analyze_file(ir_path)
    report = engine.report(print_output=True)
    findings_path = os.path.join(export_base, "findings.json")
    engine.export(findings_path)
    return ir_path, findings_path

def run_url_scan(target, export_base):
    from url_scanner import URLScanner

    print(f"\n[MISTCODER] URL scan: {target}")
    os.makedirs(export_base, exist_ok=True)
    scanner   = URLScanner()
    ir        = scanner.scan(target)
    ir_path   = os.path.join(export_base, "url_ir.json")
    scanner.export(ir, ir_path)

    # MOD-02: analyze the URL IR
    from analyzer import AnalysisEngine
    engine = AnalysisEngine()
    engine.analyze_file(ir_path)
    report = engine.report(print_output=True)
    findings_path = os.path.join(export_base, "findings.json")
    engine.export(findings_path)
    return ir_path, findings_path

def run_reasoning(ir_path, findings_path, export_base, target_name):
    from reasoning_core import ReasoningCore, ReasoningConfig

    with open(ir_path,       "r", encoding="utf-8") as f: ir          = json.load(f)
    with open(findings_path, "r", encoding="utf-8") as f: findings_doc = json.load(f)

    finding_list = findings_doc.get("findings", [])

    KIND_MAP = {
        "eval":"RCE_INJECTION","exec":"RCE_COMMAND_EXEC","execsync":"RCE_COMMAND_EXEC",
        "function":"RCE_INJECTION","os.system":"RCE_COMMAND_EXEC","os.popen":"RCE_COMMAND_EXEC",
        "subprocess":"RCE_COMMAND_EXEC","document.write":"XSS_REFLECTED","innerhtml":"XSS_REFLECTED",
        "pickle.loads":"DESERIALIZATION_UNSAFE","yaml.load":"DESERIALIZATION_UNSAFE",
        "__import__":"RCE_INJECTION","open":"PATH_TRAVERSAL",
        "js_eval":"RCE_INJECTION","js_document_write":"XSS_REFLECTED",
        "js_inner_html":"XSS_REFLECTED","cors_wildcard_with_credentials":"AUTH_BYPASS",
        "missing_header_content_security_policy":"XSS_REFLECTED",
        "secret_api_key":"CREDENTIAL","secret_openai_key":"CREDENTIAL",
        "admin_panel":"AUTH_BYPASS","git_exposed":"PATH_TRAVERSAL",
        "env_file":"CREDENTIAL","debug_endpoint":"AUTH_BYPASS",
    }

    converted = []
    for i, f in enumerate(finding_list):
        raw = f.get("call_name", f.get("kind", "UNKNOWN")).lower()
        converted.append({
            "id":         f.get("finding_id", f"f-{i+1:03d}"),
            "kind":       KIND_MAP.get(raw, raw.upper()),
            "severity":   f.get("severity", "MEDIUM"),
            "file_path":  f.get("file", f.get("file_path", target_name)),
            "line_start": f.get("line", 0),
            "line_end":   f.get("line", 0),
            "confidence": min(1.0, f.get("cvss_score", 5.0) / 10.0),
            "cwe_ids":    [f.get("cwe_id", "CWE-0")] if f.get("cwe_id") else [],
            "metadata":   {},
        })

    config = ReasoningConfig(target_name=target_name)
    core   = ReasoningCore(config)
    result = core.reason(converted)
    result.print_summary()

    reasoning_path = os.path.join(export_base, "reasoning.json")
    with open(reasoning_path, "w", encoding="utf-8") as f:
        f.write(result.to_json())
    print(f"[MOD-03] Reasoning report → {reasoning_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    target      = sys.argv[1]
    export_base = "reports/latest"

    if len(sys.argv) >= 4 and sys.argv[2] == "--export":
        export_base = os.path.dirname(sys.argv[3]) or "reports/latest"

    print(f"\n{'═'*64}")
    print(f"  MISTCODER  ·  Unified Scanner")
    print(f"  Target : {target}")
    print(f"{'═'*64}")

    if is_url(target):
        ir_path, findings_path = run_url_scan(target, export_base)
    else:
        ir_path, findings_path = run_file_scan(target, export_base)

    run_reasoning(ir_path, findings_path, export_base, target)

    print(f"\n{'═'*64}")
    print(f"  SCAN COMPLETE — reports saved to {export_base}/")
    print(f"{'═'*64}\n")
