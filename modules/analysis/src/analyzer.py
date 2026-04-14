"""
MISTCODER -- MOD-02 Static Analysis Engine
Version: 0.1.0 (skeleton)

Architecture:
    IRLoader      -- consumes MOD-01 IR JSON
    Scorer        -- CVSS-style severity scoring per finding
    TaintTracer   -- traces untrusted input to dangerous sink
    Reporter      -- ranked findings, JSON + human-readable

Data flow:
    IR JSON --> IRLoader --> findings[] --> Scorer --> TaintTracer --> Reporter
"""

import json
import os
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Constants -- Severity scoring weights (CVSS-inspired)
# ---------------------------------------------------------------------------

SEVERITY_MATRIX = {
    # call_name : (base_score, label, cwe_id, description)
    "eval":           (9.8, "CRITICAL", "CWE-95",  "Improper neutralization of directives in eval"),
    "exec":           (9.8, "CRITICAL", "CWE-78",  "OS command injection via exec"),
    "Function":       (9.1, "CRITICAL", "CWE-95",  "Code injection via Function constructor"),
    "execSync":       (9.0, "CRITICAL", "CWE-78",  "Synchronous OS command injection"),
    "os.system":      (8.8, "HIGH",     "CWE-78",  "OS command injection via os.system"),
    "os.popen":       (8.8, "HIGH",     "CWE-78",  "OS command injection via os.popen"),
    "subprocess":     (8.5, "HIGH",     "CWE-78",  "Subprocess command injection vector"),
    "document.write": (7.5, "HIGH",     "CWE-79",  "Cross-site scripting via document.write"),
    "innerHTML":      (7.5, "HIGH",     "CWE-79",  "Cross-site scripting via innerHTML"),
    "pickle.loads":   (8.0, "HIGH",     "CWE-502", "Deserialization of untrusted data"),
    "yaml.load":      (7.8, "HIGH",     "CWE-502", "Unsafe YAML deserialization"),
    "__import__":     (7.0, "HIGH",     "CWE-913", "Dynamic import code injection"),
    "compile":        (6.5, "MEDIUM",   "CWE-95",  "Dynamic code compilation"),
    "open":           (5.5, "MEDIUM",   "CWE-73",  "External control of file path"),
    "setTimeout":     (5.0, "MEDIUM",   "CWE-95",  "Deferred eval via setTimeout"),
    "setInterval":    (5.0, "MEDIUM",   "CWE-95",  "Repeated eval via setInterval"),
}

TAINT_SOURCES = {
    # Python
    "input", "request", "sys.argv", "os.environ",
    "os.getenv", "flask.request", "django.request",
    # JavaScript
    "req.body", "req.query", "req.params",
    "location.search", "document.cookie", "window.location",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class Finding:
    """
    A single confirmed security finding.

    Attributes:
        finding_id    : unique ID (FD0001, FD0002, ...)
        call_name     : the dangerous function name
        file          : source file path
        line          : line number in source
        severity      : CRITICAL / HIGH / MEDIUM / LOW
        cvss_score    : float 0.0 - 10.0
        cwe_id        : CWE reference string
        description   : human-readable issue description
        taint_path    : list of node IDs tracing input -> sink (empty if untraced)
        context       : enclosing function name if available
    """

    def __init__(self, finding_id, call_name, file, line,
                 severity, cvss_score, cwe_id, description,
                 taint_path=None, context=None):
        self.finding_id  = finding_id
        self.call_name   = call_name
        self.file        = file
        self.line        = line
        self.severity    = severity
        self.cvss_score  = cvss_score
        self.cwe_id      = cwe_id
        self.description = description
        self.taint_path  = taint_path or []
        self.context     = context

    def to_dict(self):
        return {
            "finding_id":  self.finding_id,
            "call_name":   self.call_name,
            "file":        self.file,
            "line":        self.line,
            "severity":    self.severity,
            "cvss_score":  self.cvss_score,
            "cwe_id":      self.cwe_id,
            "description": self.description,
            "taint_path":  self.taint_path,
            "context":     self.context,
        }


# ---------------------------------------------------------------------------
# L1 -- IRLoader
# ---------------------------------------------------------------------------

class IRLoader:
    """
    Loads one or more MOD-01 IR JSON files.
    Returns a unified list of IR documents ready for analysis.
    """

    def load_file(self, path):
        """Load a single IR JSON file."""
        if not os.path.isfile(path):
            raise FileNotFoundError(f"IR file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def load_directory(self, dirpath, pattern=".json"):
        """Load all IR JSON files from a directory."""
        results = []
        for fname in os.listdir(dirpath):
            if fname.endswith(pattern):
                full = os.path.join(dirpath, fname)
                try:
                    results.append(self.load_file(full))
                except Exception as e:
                    print(f"[MOD-02][IRLoader] WARN: could not load {full}: {e}")
        return results

    def validate(self, ir):
        """
        Validate IR structure from MOD-01.
        Returns (True, None) or (False, reason_string).
        """
        required = {"file", "language", "nodes", "edges", "metadata"}
        missing  = required - set(ir.keys())
        if missing:
            return False, f"Missing IR fields: {missing}"
        if not isinstance(ir["nodes"], list):
            return False, "nodes must be a list"
        if not isinstance(ir["edges"], list):
            return False, "edges must be a list"
        return True, None


# ---------------------------------------------------------------------------
# L2 -- Scorer
# ---------------------------------------------------------------------------

class Scorer:
    """
    Assigns CVSS-style severity scores to dangerous call nodes.

    Scoring factors (v0.1.0):
        base_score  : from SEVERITY_MATRIX (call type)
        context_mod : -0.5 if call is inside a class method (reduced exposure)
        secret_boost: +0.3 if a secret_flag node exists in the same file

    Future factors (v0.2.0+):
        taint_confirmed : +1.0 if TaintTracer confirms untrusted input reaches sink
        network_exposed : +0.5 if enclosing function handles HTTP request object
    """

    def __init__(self):
        self._finding_counter = 0

    def _next_id(self):
        self._finding_counter += 1
        return f"FD{self._finding_counter:04d}"

    def score(self, ir):
        """
        Score all dangerous call nodes in one IR document.
        Returns list of Finding objects.
        """
        findings    = []
        nodes       = ir.get("nodes", [])
        edges       = ir.get("edges", [])
        file_path   = ir.get("file", "unknown")

        has_secrets = any(n["type"] == "secret_flag" for n in nodes)

        # build node lookup
        node_map = {n["id"]: n for n in nodes}

        # build reverse edge map: call_id -> parent_function_id
        parent_map = {}
        for edge in edges:
            if edge["type"] == "calls":
                parent_map[edge["dst"]] = edge["src"]

        for node in nodes:
            if node.get("props", {}).get("dangerous"):
                call_name = node["name"]
                matrix    = SEVERITY_MATRIX.get(
                    call_name,
                    (4.0, "LOW", "CWE-0", "Dangerous call (unclassified)")
                )
                base_score, label, cwe_id, description = matrix

                # context modifier
                parent_id   = parent_map.get(node["id"])
                parent_node = node_map.get(parent_id) if parent_id else None
                context_name = parent_node["name"] if parent_node else None

                score = base_score
                if parent_node and parent_node["type"] == "function":
                    score -= 0.0   # placeholder; network_exposed check in v0.2.0

                # secret boost
                if has_secrets:
                    score = min(10.0, score + 0.3)

                findings.append(Finding(
                    finding_id  = self._next_id(),
                    call_name   = call_name,
                    file        = file_path,
                    line        = node["line"],
                    severity    = label,
                    cvss_score  = round(score, 1),
                    cwe_id      = cwe_id,
                    description = description,
                    taint_path  = [],        # filled by TaintTracer
                    context     = context_name,
                ))

        return findings


# ---------------------------------------------------------------------------
# L3 -- TaintTracer
# ---------------------------------------------------------------------------

class TaintTracer:
    """
    Traces untrusted input from taint sources to dangerous sinks.

    Algorithm (v0.1.0 -- inter-procedural stub):
        1. Mark all function parameters as tainted if the function name
           or any parameter name matches a TAINT_SOURCE pattern.
        2. Walk edges from tainted nodes to dangerous call nodes.
        3. If a path exists, attach it to the Finding and boost score.

    Full inter-procedural data-flow analysis is a v0.3.0 target.
    Current implementation covers direct single-function taint only.
    """

    def trace(self, ir, findings):
        """
        Attempt to trace taint for each finding.
        Mutates finding.taint_path in place.
        Returns findings list (same reference).
        """
        nodes  = ir.get("nodes", [])
        edges  = ir.get("edges", [])

        # build forward adjacency: src -> [dst, ...]
        fwd = {}
        for edge in edges:
            fwd.setdefault(edge["src"], []).append(edge["dst"])

        node_map = {n["id"]: n for n in nodes}

        # identify taint source nodes
        taint_seeds = set()
        for node in nodes:
            if node["type"] == "function":
                args = node.get("props", {}).get("args", [])
                for arg in args:
                    if any(s in arg.lower() for s in TAINT_SOURCES):
                        taint_seeds.add(node["id"])

        # BFS from each seed to find reachable dangerous calls
        def bfs(start):
            visited = set()
            queue   = [(start, [start])]
            paths   = []
            while queue:
                current, path = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)
                n = node_map.get(current)
                if n and n.get("props", {}).get("dangerous"):
                    paths.append(path)
                for nxt in fwd.get(current, []):
                    if nxt not in visited:
                        queue.append((nxt, path + [nxt]))
            return paths

        # match paths to findings by line number
        dangerous_by_line = {}
        for finding in findings:
            dangerous_by_line.setdefault(finding.line, []).append(finding)

        for seed in taint_seeds:
            for path in bfs(seed):
                sink_id   = path[-1]
                sink_node = node_map.get(sink_id)
                if sink_node:
                    for finding in dangerous_by_line.get(sink_node["line"], []):
                        if not finding.taint_path:
                            finding.taint_path = path
                            # taint confirmed: boost score
                            finding.cvss_score = min(10.0, finding.cvss_score + 1.0)
                            if finding.cvss_score >= 9.0:
                                finding.severity = "CRITICAL"

        return findings


# ---------------------------------------------------------------------------
# L4 -- Reporter
# ---------------------------------------------------------------------------

class Reporter:
    """
    Generates the final findings report in two formats:
        1. Structured JSON  -- machine-readable, CI/CD friendly
        2. Human report     -- terminal-readable ranked summary
    """

    def generate(self, findings, meta=None):
        """
        Build the full report structure.
        Returns a dict ready for JSON serialization or terminal print.
        """
        sorted_findings = sorted(
            findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.cvss_score)
        )

        summary = {
            "total":    len(findings),
            "critical": sum(1 for f in findings if f.severity == "CRITICAL"),
            "high":     sum(1 for f in findings if f.severity == "HIGH"),
            "medium":   sum(1 for f in findings if f.severity == "MEDIUM"),
            "low":      sum(1 for f in findings if f.severity == "LOW"),
        }

        return {
            "engine":    "MISTCODER MOD-02 Static Analysis Engine v0.1.0",
            "generated": datetime.now(timezone.utc).isoformat(),
            "meta":      meta or {},
            "summary":   summary,
            "findings":  [f.to_dict() for f in sorted_findings],
        }

    def print_report(self, report):
        """Print human-readable report to terminal."""
        s = report["summary"]
        print()
        print("=" * 70)
        print("  MISTCODER -- MOD-02 STATIC ANALYSIS REPORT")
        print(f"  Generated : {report['generated']}")
        print("=" * 70)
        print(f"  SUMMARY   CRITICAL:{s['critical']}  HIGH:{s['high']}  "
              f"MEDIUM:{s['medium']}  LOW:{s['low']}  TOTAL:{s['total']}")
        print("=" * 70)

        for f in report["findings"]:
            taint = " [TAINT CONFIRMED]" if f["taint_path"] else ""
            print(f"\n  [{f['severity']:8s}] {f['finding_id']}  score={f['cvss_score']}"
                  f"  {f['cwe_id']}{taint}")
            print(f"  Call    : {f['call_name']}")
            print(f"  File    : {f['file']}  line {f['line']}")
            if f["context"]:
                print(f"  Context : inside function '{f['context']}'")
            print(f"  Issue   : {f['description']}")
            if f["taint_path"]:
                print(f"  Path    : {' --> '.join(f['taint_path'])}")

        print()
        print("=" * 70)
        print("  END OF REPORT")
        print("=" * 70)
        print()

    def export_json(self, report, output_path):
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"[MOD-02] Report exported to {output_path}")


# ---------------------------------------------------------------------------
# AnalysisEngine -- orchestrates all four layers
# ---------------------------------------------------------------------------

class AnalysisEngine:
    """
    Top-level orchestrator for MOD-02.

    Usage:
        engine = AnalysisEngine()
        engine.analyze_file("sandbox/sample_ir_output.json")
        engine.analyze_file("sandbox/sample_js_ir_output.json")
        report = engine.report()
        engine.export("reports/findings_v1.json")
    """

    def __init__(self):
        self.loader   = IRLoader()
        self.scorer   = Scorer()
        self.tracer   = TaintTracer()
        self.reporter = Reporter()
        self._all_findings = []
        self._ir_files     = []

    def analyze_file(self, ir_path):
        ir      = self.loader.load_file(ir_path)
        valid, reason = self.loader.validate(ir)
        if not valid:
            print(f"[MOD-02] WARN: invalid IR at {ir_path}: {reason}")
            return []

        findings = self.scorer.score(ir)
        findings = self.tracer.trace(ir, findings)
        self._all_findings.extend(findings)
        self._ir_files.append(ir_path)
        return findings

    def analyze_directory(self, dir_path):
        irs = self.loader.load_directory(dir_path)
        for ir in irs:
            findings = self.scorer.score(ir)
            findings = self.tracer.trace(ir, findings)
            self._all_findings.extend(findings)

    def report(self, print_output=True):
        meta   = {"ir_files": self._ir_files}
        report = self.reporter.generate(self._all_findings, meta=meta)
        if print_output:
            self.reporter.print_report(report)
        return report

    def export(self, output_path):
        meta   = {"ir_files": self._ir_files}
        report = self.reporter.generate(self._all_findings, meta=meta)
        self.reporter.export_json(report, output_path)
        return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <ir_file_or_dir> [--export output.json]")
        sys.exit(1)

    target = sys.argv[1]
    export = sys.argv[3] if len(sys.argv) >= 4 and sys.argv[2] == "--export" else None

    engine = AnalysisEngine()

    if os.path.isdir(target):
        engine.analyze_directory(target)
    else:
        engine.analyze_file(target)

    report = engine.report(print_output=True)

    if export:
        engine.export(export)
