"""
MISTCODER -- HTML Report Generator v0.1.0
Converts MOD-01 + MOD-02 + MOD-03 pipeline output into a
professional penetration testing report.
Standalone HTML output. No external dependencies.
"""

import json
import os
import html as html_lib
from datetime import datetime, timezone

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

BADGE = {
    "critical": "background:#c0392b;color:#fff;",
    "high":     "background:#e67e22;color:#fff;",
    "medium":   "background:#e6a817;color:#000;",
    "low":      "background:#27ae60;color:#fff;",
    "info":     "background:#2980b9;color:#fff;",
}

RISK_HEX = {
    "critical": "#c0392b",
    "high":     "#e67e22",
    "medium":   "#e6a817",
    "low":      "#27ae60",
}

CHAIN_BORDER = {
    "critical": "#c0392b",
    "high":     "#e67e22",
    "medium":   "#e6a817",
    "low":      "#27ae60",
}

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;
     font-size:14px;line-height:1.6;color:#1a1a2e;background:#f4f5f7}
.cover{background:#1a1a2e;color:#fff;padding:56px 64px 44px}
.cover-logo{font-size:28px;font-weight:700;letter-spacing:5px;
            color:#e74c3c;margin-bottom:6px}
.cover-sub{font-size:11px;letter-spacing:2px;color:#7777aa;
           text-transform:uppercase;margin-bottom:44px}
.confid{display:inline-block;background:#e74c3c;color:#fff;font-size:10px;
        letter-spacing:2px;text-transform:uppercase;padding:5px 14px;
        margin-bottom:20px}
.cover-title{font-size:20px;font-weight:600;color:#fff;margin-bottom:4px}
.cover-target{font-size:13px;color:#9999bb;margin-bottom:36px}
.cover-meta{display:flex;gap:44px}
.cover-meta-item label{font-size:10px;text-transform:uppercase;
                        letter-spacing:1px;color:#555577;display:block}
.cover-meta-item span{font-size:15px;font-weight:600}
.main{max-width:940px;margin:0 auto;padding:40px 28px}
.sec{margin-bottom:48px}
.sec-title{font-size:17px;font-weight:600;color:#1a1a2e;
           border-bottom:2px solid #e74c3c;padding-bottom:8px;
           margin-bottom:22px}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;
         margin-bottom:28px}
.mc{background:#fff;border:1px solid #dde0e6;border-radius:8px;
    padding:18px 20px;text-align:center}
.mc .n{font-size:30px;font-weight:700;line-height:1}
.mc .l{font-size:11px;text-transform:uppercase;letter-spacing:1px;
       color:#888;margin-top:6px}
.mc.cr .n{color:#c0392b}.mc.hi .n{color:#e67e22}
.mc.me .n{color:#e6a817}.mc.to .n{color:#1a1a2e}
table{width:100%;border-collapse:collapse;background:#fff;
      border:1px solid #dde0e6;border-radius:8px;overflow:hidden}
th{background:#1a1a2e;color:#fff;padding:11px 14px;text-align:left;
   font-size:11px;text-transform:uppercase;letter-spacing:1px;font-weight:500}
td{padding:11px 14px;border-bottom:1px solid #f0f1f4;vertical-align:top}
tr:last-child td{border-bottom:none}
tr:nth-child(even){background:#fafbfc}
.badge{display:inline-block;padding:2px 9px;border-radius:3px;
       font-size:10px;font-weight:700;letter-spacing:.5px;text-transform:uppercase}
.chain-card{background:#fff;border:1px solid #dde0e6;
            border-left:4px solid #888;border-radius:8px;
            padding:18px 22px;margin-bottom:14px}
.chain-hdr{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.chain-id{font-size:11px;color:#888;font-family:monospace}
.chain-narr{font-size:13px;color:#444;line-height:1.75}
.exec{background:#fff;border:1px solid #dde0e6;border-radius:8px;
      padding:22px 26px}
.exec p{margin-bottom:10px;color:#333;line-height:1.8}
.exec p:last-child{margin-bottom:0}
.risk-row{display:flex;align-items:center;gap:14px;padding:18px 22px;
          background:#fff;border:1px solid #dde0e6;border-radius:8px;
          margin-bottom:22px}
.risk-dot{width:18px;height:18px;border-radius:50%;flex-shrink:0}
.risk-val{font-size:18px;font-weight:700;text-transform:uppercase}
.risk-lbl{font-size:12px;color:#888}
.foot{background:#1a1a2e;color:#444466;text-align:center;
      padding:22px;font-size:11px;margin-top:40px}
.empty{color:#aaa;font-style:italic;padding:16px 0}
pre{background:#f4f5f7;border:1px solid #dde0e6;border-radius:4px;
    padding:10px 14px;font-size:11px;overflow-x:auto;
    white-space:pre-wrap;word-break:break-all}
.path-row td:first-child{font-family:monospace;font-size:12px;color:#555}
.conf-bar{display:inline-block;height:6px;border-radius:3px;
          background:#e74c3c;vertical-align:middle}
"""


def _e(text):
    return html_lib.escape(str(text)) if text else ""


def _badge(severity):
    sev = (severity or "info").lower()
    style = BADGE.get(sev, BADGE["info"])
    return f'<span class="badge" style="{style}">{_e(sev)}</span>'


def _risk_indicator(risk, report_data):
    color = RISK_HEX.get(risk, "#888")
    return (
        f'<div class="risk-row">'
        f'<div class="risk-dot" style="background:{color}"></div>'
        f'<div><div class="risk-val" style="color:{color}">{_e(risk)}</div>'
        f'<div class="risk-lbl">Overall risk rating</div></div>'
        f'</div>'
    )


def _metrics(findings, threat_model):
    total    = len(findings)
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high     = sum(1 for f in findings if f.get("severity") == "high")
    medium   = sum(1 for f in findings if f.get("severity") == "medium")
    return (
        f'<div class="metrics">'
        f'<div class="mc to"><div class="n">{total}</div>'
        f'<div class="l">Total findings</div></div>'
        f'<div class="mc cr"><div class="n">{critical}</div>'
        f'<div class="l">Critical</div></div>'
        f'<div class="mc hi"><div class="n">{high}</div>'
        f'<div class="l">High</div></div>'
        f'<div class="mc me"><div class="n">{medium}</div>'
        f'<div class="l">Medium</div></div>'
        f'</div>'
    )


def _exec_summary(target, risk, findings, chains, anomalies, metadata):
    total    = len(findings)
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    chain_ct = len(chains)
    anom_ct  = len(anomalies)

    risk_sentence = {
        "critical": "The target presents a <strong>critical</strong> risk posture. Immediate remediation is required before continued operation.",
        "high":     "The target presents a <strong>high</strong> risk posture. Remediation of priority findings should be treated as urgent.",
        "medium":   "The target presents a <strong>medium</strong> risk posture. Findings should be addressed in the next development cycle.",
        "low":      "The target presents a <strong>low</strong> risk posture. Minor improvements are recommended.",
    }.get(risk, "The risk posture could not be determined.")

    chain_sentence = (
        f"MISTCODER identified {chain_ct} vulnerability chain(s) — cases where "
        f"individually minor weaknesses combine to create a complete breach path."
        if chain_ct > 0 else
        "No multi-step vulnerability chains were detected."
    )

    anom_sentence = (
        f"{anom_ct} behavioral anomaly(s) were flagged — functions that violate "
        f"expected security contracts for their category, beyond known CVE signatures."
        if anom_ct > 0 else
        "No behavioral anomalies were detected beyond the findings listed."
    )

    return (
        f'<div class="exec">'
        f'<p>{risk_sentence}</p>'
        f'<p>MISTCODER completed a full five-stage intelligence pipeline on '
        f'<strong>{_e(target)}</strong>, producing {total} finding(s) across '
        f'all severity tiers'
        + (f', including {critical} critical-severity item(s)' if critical else '') +
        f'.</p>'
        f'<p>{chain_sentence}</p>'
        f'<p>{anom_sentence}</p>'
        f'</div>'
    )


def _findings_table(findings):
    if not findings:
        return '<p class="empty">No findings recorded for this target.</p>'

    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 4)
    )

    rows = ""
    for f in sorted_findings:
        fid   = _e(f.get("id", "--"))
        cat   = _e(f.get("category", "--"))
        sev   = f.get("severity", "info")
        desc  = _e(f.get("description", "--"))
        line  = _e(f.get("line", "--"))
        rows += (
            f"<tr>"
            f"<td style='font-family:monospace;font-size:12px'>{fid}</td>"
            f"<td>{cat}</td>"
            f"<td>{_badge(sev)}</td>"
            f"<td>{desc}</td>"
            f"<td style='text-align:center'>{line}</td>"
            f"</tr>"
        )

    return (
        f"<table>"
        f"<thead><tr>"
        f"<th>ID</th><th>Category</th><th>Severity</th>"
        f"<th>Description</th><th>Line</th>"
        f"</tr></thead>"
        f"<tbody>{rows}</tbody>"
        f"</table>"
    )


def _chains_section(chains):
    if not chains:
        return '<p class="empty">No vulnerability chains detected.</p>'

    out = ""
    for ch in chains:
        sev      = ch.get("combined_severity", "medium")
        color    = CHAIN_BORDER.get(sev, "#888")
        chain_id = _e(ch.get("id", "--"))
        narr     = _e(ch.get("narrative", ""))
        conf     = ch.get("confidence", 0)
        conf_w   = int(conf * 80)
        out += (
            f'<div class="chain-card" style="border-left-color:{color}">'
            f'<div class="chain-hdr">'
            f'{_badge(sev)}'
            f'<span class="chain-id">{chain_id}</span>'
            f'<span style="font-size:11px;color:#aaa;margin-left:auto">'
            f'confidence '
            f'<span class="conf-bar" style="width:{conf_w}px"></span>'
            f' {int(conf * 100)}%</span>'
            f'</div>'
            f'<div class="chain-narr">{narr}</div>'
            f'</div>'
        )
    return out


def _paths_section(attack_paths):
    if not attack_paths:
        return '<p class="empty">No attack paths enumerated.</p>'

    top = sorted(
        attack_paths,
        key=lambda p: SEVERITY_ORDER.get(p.get("severity", "info"), 4)
    )[:10]

    rows = ""
    for p in top:
        pid   = _e(p.get("id", "--"))
        sev   = p.get("severity", "info")
        conf  = p.get("confidence", 0)
        desc  = _e(p.get("description", "--"))
        nodes = len(p.get("nodes", []))
        rows += (
            f"<tr class='path-row'>"
            f"<td>{pid}</td>"
            f"<td>{_badge(sev)}</td>"
            f"<td style='text-align:center'>{nodes}</td>"
            f"<td style='text-align:center'>{int(conf * 100)}%</td>"
            f"<td>{desc}</td>"
            f"</tr>"
        )

    return (
        f"<table>"
        f"<thead><tr>"
        f"<th>Path ID</th><th>Severity</th>"
        f"<th>Nodes</th><th>Confidence</th><th>Description</th>"
        f"</tr></thead>"
        f"<tbody>{rows}</tbody>"
        f"</table>"
    )


def _anomalies_section(anomalies):
    if not anomalies:
        return '<p class="empty">No behavioral anomalies detected.</p>'

    rows = ""
    for a in anomalies:
        aid  = _e(a.get("id", "--"))
        fn   = _e(a.get("function_name", "--"))
        cat  = _e(a.get("category", "--"))
        sev  = a.get("severity", "medium")
        viol = _e(a.get("violation", "--"))
        line = _e(a.get("line", "--"))
        rows += (
            f"<tr class='anomaly-row'>"
            f"<td>{fn}</td>"
            f"<td>{cat}</td>"
            f"<td>{_badge(sev)}</td>"
            f"<td>{viol}</td>"
            f"<td style='text-align:center'>{line}</td>"
            f"</tr>"
        )

    return (
        f"<table>"
        f"<thead><tr>"
        f"<th>Function</th><th>Category</th><th>Severity</th>"
        f"<th>Violation</th><th>Line</th>"
        f"</tr></thead>"
        f"<tbody>{rows}</tbody>"
        f"</table>"
    )


def _appendix(ir_metadata, analysis_metadata, reasoning_metadata, target):
    items = {
        "Target":              target,
        "Language":            ir_metadata.get("language", "--"),
        "Parser":              ir_metadata.get("parser", "--"),
        "Analyzer":            analysis_metadata.get("analyzer", "--"),
        "Reasoner":            reasoning_metadata.get("reasoner", "--"),
        "IR Nodes":            str(ir_metadata.get("node_count", "--")),
        "IR Edges":            str(ir_metadata.get("edge_count", "--")),
        "Graph nodes":         str(reasoning_metadata.get("graph_node_count", "--")),
        "Graph edges":         str(reasoning_metadata.get("graph_edge_count", "--")),
        "Taint flows":         str(analysis_metadata.get("taint_flow_count", "--")),
        "CFG functions":       str(analysis_metadata.get("cfg_function_count", "--")),
        "Attack paths found":  str(reasoning_metadata.get("attack_path_count", "--")),
        "Chains detected":     str(reasoning_metadata.get("chain_count", "--")),
        "Anomalies":           str(reasoning_metadata.get("anomaly_count", "--")),
        "Analyzed at":         analysis_metadata.get("analyzed_at", "--"),
        "Reasoned at":         reasoning_metadata.get("reasoned_at", "--"),
    }
    rows = "".join(
        f"<tr><td style='color:#888;width:200px'>{k}</td>"
        f"<td style='font-family:monospace'>{_e(v)}</td></tr>"
        for k, v in items.items()
    )
    return (
        f"<table><thead><tr><th>Property</th><th>Value</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def generate(ir, analysis_report, reasoning_result, output_path,
             target_label=None, analyst_name=None, classification=None):
    """
    Generate a standalone HTML security report.

    Parameters
    ----------
    ir               : dict  MOD-01 output
    analysis_report  : dict  MOD-02 output
    reasoning_result : dict  MOD-03 output (may be None)
    output_path      : str   path to write HTML file
    target_label     : str   human-readable target name
    analyst_name     : str   analyst or tool label
    classification   : str   report classification string
    """
    now       = datetime.now(timezone.utc)
    date_str  = now.strftime("%d %B %Y")
    time_str  = now.strftime("%H:%M UTC")
    target    = target_label or ir.get("file", "Unknown Target")
    analyst   = analyst_name or "MISTCODER Autonomous Pipeline"
    classif   = classification or "CONFIDENTIAL"

    findings  = analysis_report.get("findings", [])
    ir_meta   = analysis_report.get("metadata", {})
    ana_meta  = analysis_report.get("metadata", {})

    if reasoning_result:
        tm       = reasoning_result.get("threat_model", {})
        risk     = tm.get("overall_risk", "low")
        chains   = reasoning_result.get("chains", [])
        paths    = reasoning_result.get("attack_paths", [])
        anomalies = reasoning_result.get("anomalies", [])
        rea_meta = reasoning_result.get("metadata", {})
    else:
        risk      = "low"
        chains    = []
        paths     = []
        anomalies = []
        rea_meta  = {}

    ir_m = ir.get("metadata", {})

    risk_color = RISK_HEX.get(risk, "#888")

    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MISTCODER Security Report -- {_e(target)}</title>
<style>{CSS}</style>
</head>
<body>

<div class="cover">
  <div class="cover-logo">MISTCODER</div>
  <div class="cover-sub">Multi-Intelligence Security &amp; Threat Cognition</div>
  <div class="confid">{_e(classif)}</div>
  <div class="cover-title">Security Analysis Report</div>
  <div class="cover-target">{_e(target)}</div>
  <div class="cover-meta">
    <div class="cover-meta-item">
      <label>Date</label>
      <span>{_e(date_str)}</span>
    </div>
    <div class="cover-meta-item">
      <label>Time</label>
      <span>{_e(time_str)}</span>
    </div>
    <div class="cover-meta-item">
      <label>Analyst</label>
      <span>{_e(analyst)}</span>
    </div>
    <div class="cover-meta-item">
      <label>Overall risk</label>
      <span style="color:{risk_color}">{_e(risk.upper())}</span>
    </div>
  </div>
</div>

<div class="main">

  <div class="sec">
    <div class="sec-title">Executive Summary</div>
    {_risk_indicator(risk, reasoning_result)}
    {_exec_summary(target, risk, findings, chains, anomalies, ana_meta)}
  </div>

  <div class="sec">
    <div class="sec-title">Finding Summary</div>
    {_metrics(findings, tm if reasoning_result else {})}
    {_findings_table(findings)}
  </div>

  <div class="sec">
    <div class="sec-title">Vulnerability Chains</div>
    {_chains_section(chains)}
  </div>

  <div class="sec">
    <div class="sec-title">Attack Paths</div>
    {_paths_section(paths)}
  </div>

  <div class="sec">
    <div class="sec-title">Behavioral Anomalies</div>
    {_anomalies_section(anomalies)}
  </div>

  <div class="sec">
    <div class="sec-title">Technical Appendix</div>
    {_appendix(ir_m, ana_meta, rea_meta, target)}
  </div>

</div>

<div class="foot">
  MISTCODER Security Analysis Report &nbsp;|&nbsp;
  Generated {_e(date_str)} at {_e(time_str)} &nbsp;|&nbsp;
  {_e(classif)} &nbsp;|&nbsp;
  Do not distribute without authorization
</div>

</body>
</html>"""

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_out)

    return output_path


class ReportGenerator:
    """
    MOD-06 entry point.
    Wraps the generate() function with a class interface
    for pipeline integration.
    """

    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir

    def generate_report(self, ir, analysis_report,
                        reasoning_result=None,
                        filename=None,
                        target_label=None,
                        analyst_name=None,
                        classification=None):
        if not filename:
            ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            safe     = (target_label or "target").replace("/", "_").replace(":", "")
            filename = f"MISTCODER_{safe}_{ts}.html"

        output_path = os.path.join(self.output_dir, filename)
        path = generate(
            ir               = ir,
            analysis_report  = analysis_report,
            reasoning_result = reasoning_result,
            output_path      = output_path,
            target_label     = target_label,
            analyst_name     = analyst_name,
            classification   = classification,
        )
        print(f"[MOD-06] Report generated: {path}")
        return path

    def generate_from_json_files(self, ir_path, analysis_path,
                                 reasoning_path=None,
                                 target_label=None,
                                 output_path=None):
        with open(ir_path, "r", encoding="utf-8") as f:
            ir = json.load(f)
        with open(analysis_path, "r", encoding="utf-8") as f:
            analysis_report = json.load(f)
        reasoning_result = None
        if reasoning_path:
            with open(reasoning_path, "r", encoding="utf-8") as f:
                reasoning_result = json.load(f)

        filename    = os.path.basename(output_path) if output_path else None
        output_dir  = os.path.dirname(output_path) if output_path else self.output_dir
        self.output_dir = output_dir or self.output_dir
        return self.generate_report(
            ir               = ir,
            analysis_report  = analysis_report,
            reasoning_result = reasoning_result,
            filename         = filename,
            target_label     = target_label,
        )


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python report_generator.py <ir.json> <analysis.json> "
              "[reasoning.json] [--out output.html] [--target 'Target Name']")
        sys.exit(1)

    ir_p      = sys.argv[1]
    ana_p     = sys.argv[2]
    rea_p     = None
    out_p     = "reports/report.html"
    target_l  = None

    i = 3
    while i < len(sys.argv):
        if sys.argv[i] == "--out" and i + 1 < len(sys.argv):
            out_p = sys.argv[i + 1]; i += 2
        elif sys.argv[i] == "--target" and i + 1 < len(sys.argv):
            target_l = sys.argv[i + 1]; i += 2
        elif not rea_p and not sys.argv[i].startswith("--"):
            rea_p = sys.argv[i]; i += 1
        else:
            i += 1

    gen  = ReportGenerator(output_dir=os.path.dirname(out_p) or "reports")
    path = gen.generate_from_json_files(
        ir_p, ana_p, rea_p,
        target_label = target_l,
        output_path  = out_p
    )
    print(f"[MOD-06] Report ready: {path}")
