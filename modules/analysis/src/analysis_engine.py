"""
MISTCODER -- MOD-02 Static Analysis Engine
Taint Flow + Control Flow Graph Construction v0.1.0

Consumes normalized IR from MOD-01 and produces:
    -- Taint flow records  (untrusted input paths through the codebase)
    -- Control flow graph  (CFG) per function
    -- Analysis report     (JSON) passed to MOD-03

Input schema  (from MOD-01):
    ir["nodes"]  -- list of NodeRecords
    ir["edges"]  -- list of EdgeRecords

Output schema:
    {
        "file":         str,
        "language":     str,
        "taint_flows":  [ TaintRecord ],
        "cfg":          { function_name: CFGRecord },
        "findings":     [ FindingRecord ],
        "metadata":     { ... }
    }
"""

import json
from datetime import datetime, timezone
from collections import defaultdict, deque


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Sources -- nodes where untrusted input enters the system
TAINT_SOURCES = {
    "python": {
        "input", "request", "sys.argv", "os.environ",
        "flask.request", "django.request", "socket.recv",
        "open", "read", "readline"
    },
    "javascript": {
        "req.body", "req.query", "req.params", "process.argv",
        "document.cookie", "location.search", "localStorage.getItem",
        "window.location", "fetch", "axios"
    }
}

# Sinks -- nodes where tainted data causes harm if it arrives unvalidated
TAINT_SINKS = {
    "python": {
        "eval", "exec", "os.system", "os.popen",
        "subprocess.run", "subprocess.call", "subprocess.Popen",
        "pickle.loads", "yaml.load", "open",
        "cursor.execute", "db.execute", "query"
    },
    "javascript": {
        "eval", "innerHTML", "document.write",
        "execSync", "exec", "setTimeout", "setInterval",
        "Function", "db.query", "connection.query"
    }
}

# Sanitizers -- nodes that clean tainted data
SANITIZERS = {
    "python":     {"escape", "sanitize", "validate", "clean", "bleach", "quote"},
    "javascript": {"escape", "sanitize", "encodeURIComponent",
                   "DOMPurify.sanitize", "validator.escape"}
}

SEVERITY = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
    "info":     0
}


# ---------------------------------------------------------------------------
# Data records
# ---------------------------------------------------------------------------

def make_taint_record(source_node, sink_node, path, sanitized, language):
    return {
        "source":     source_node,
        "sink":       sink_node,
        "path":       path,
        "sanitized":  sanitized,
        "severity":   "info" if sanitized else _taint_severity(sink_node, language)
    }

def make_finding(finding_id, category, description, line, severity, node_id=None):
    return {
        "id":          finding_id,
        "category":    category,
        "description": description,
        "line":        line,
        "severity":    severity,
        "node_id":     node_id
    }

def _taint_severity(sink_name, language):
    critical_sinks = {"eval", "exec", "os.system", "pickle.loads",
                      "execSync", "innerHTML"}
    high_sinks     = {"subprocess.run", "subprocess.call", "cursor.execute",
                      "db.query", "document.write"}
    if sink_name in critical_sinks:
        return "critical"
    if sink_name in high_sinks:
        return "high"
    return "medium"


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------

class IRGraph:
    """
    Builds an adjacency structure from MOD-01 IR nodes and edges.
    Supports forward and reverse traversal.
    """

    def __init__(self, nodes, edges):
        self.nodes      = {n["id"]: n for n in nodes}
        self.forward    = defaultdict(list)
        self.backward   = defaultdict(list)

        for e in edges:
            self.forward[e["src"]].append(e["dst"])
            self.backward[e["dst"]].append(e["src"])

    def get_node(self, node_id):
        return self.nodes.get(node_id)

    def successors(self, node_id):
        return self.forward.get(node_id, [])

    def predecessors(self, node_id):
        return self.backward.get(node_id, [])

    def bfs_forward(self, start_id):
        visited = []
        queue   = deque([start_id])
        seen    = {start_id}
        while queue:
            current = queue.popleft()
            visited.append(current)
            for nxt in self.successors(current):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        return visited

    def all_paths(self, src_id, dst_id, max_depth=10):
        """
        Enumerate all simple paths from src to dst up to max_depth.
        Returns list of path lists.
        """
        results = []
        stack   = [(src_id, [src_id])]
        while stack:
            current, path = stack.pop()
            if current == dst_id:
                results.append(path)
                continue
            if len(path) >= max_depth:
                continue
            for nxt in self.successors(current):
                if nxt not in path:
                    stack.append((nxt, path + [nxt]))
        return results


# ---------------------------------------------------------------------------
# Taint analysis
# ---------------------------------------------------------------------------

class TaintAnalyzer:
    """
    Traces untrusted input (sources) to dangerous operations (sinks).
    Checks whether a sanitizer appears on the path.
    """

    def __init__(self, graph, language):
        self.graph     = graph
        self.language  = language
        self.sources   = TAINT_SOURCES.get(language, set())
        self.sinks     = TAINT_SINKS.get(language, set())
        self.sanitizers = SANITIZERS.get(language, set())

    def _is_source(self, node):
        name = node.get("name", "")
        return (node.get("type") in ("call", "import") and
                any(s in name for s in self.sources))

    def _is_sink(self, node):
        name = node.get("name", "")
        return (node.get("type") == "call" and
                any(s in name for s in self.sinks))

    def _is_sanitizer(self, node):
        name = node.get("name", "")
        return any(s in name for s in self.sanitizers)

    def _path_sanitized(self, path_ids):
        for nid in path_ids:
            node = self.graph.get_node(nid)
            if node and self._is_sanitizer(node):
                return True
        return False

    def analyze(self):
        taint_flows = []
        source_ids  = [nid for nid, n in self.graph.nodes.items()
                       if self._is_source(n)]
        sink_ids    = {nid for nid, n in self.graph.nodes.items()
                       if self._is_sink(n)}

        for src_id in source_ids:
            reachable = self.graph.bfs_forward(src_id)
            for reached_id in reachable:
                if reached_id in sink_ids:
                    paths      = self.graph.all_paths(src_id, reached_id)
                    src_node   = self.graph.get_node(src_id)
                    sink_node  = self.graph.get_node(reached_id)
                    for path in paths:
                        sanitized = self._path_sanitized(path)
                        taint_flows.append(
                            make_taint_record(
                                source_node = src_node["name"],
                                sink_node   = sink_node["name"],
                                path        = path,
                                sanitized   = sanitized,
                                language    = self.language
                            )
                        )
        return taint_flows


# ---------------------------------------------------------------------------
# Control flow graph construction (function-level)
# ---------------------------------------------------------------------------

class CFGBuilder:
    """
    Constructs a simplified control flow graph per function.
    Nodes are function-scoped call and assignment records from the IR.
    """

    def __init__(self, graph):
        self.graph = graph

    def build(self):
        cfg      = {}
        fn_nodes = [n for n in self.graph.nodes.values()
                    if n["type"] == "function"]

        for fn in fn_nodes:
            fn_id    = fn["id"]
            children = self.graph.bfs_forward(fn_id)
            child_nodes = [self.graph.get_node(c) for c in children
                           if self.graph.get_node(c)]
            cfg[fn["name"]] = {
                "entry":    fn_id,
                "nodes":    [fn] + child_nodes,
                "edges":    [
                    {"src": fn_id, "dst": c, "type": "cfg_edge"}
                    for c in self.graph.successors(fn_id)
                ],
                "node_count": len(child_nodes) + 1
            }
        return cfg


# ---------------------------------------------------------------------------
# Finding generator
# ---------------------------------------------------------------------------

class FindingGenerator:
    """
    Converts taint flows and raw IR observations into structured findings.
    """

    def __init__(self, taint_flows, nodes, language):
        self.taint_flows = taint_flows
        self.nodes       = nodes
        self.language    = language
        self._fid        = 0

    def _next_fid(self):
        self._fid += 1
        return f"MIST-{self._fid:05d}"

    def generate(self):
        findings = []

        # Taint flow findings
        for flow in self.taint_flows:
            if not flow["sanitized"]:
                findings.append(make_finding(
                    finding_id  = self._next_fid(),
                    category    = "TAINT_FLOW",
                    description = (
                        f"Unsanitized data flows from '{flow['source']}' "
                        f"to '{flow['sink']}' with no sanitizer on path."
                    ),
                    line        = None,
                    severity    = flow["severity"],
                ))

        # Dangerous call findings
        for node in self.nodes:
            if node.get("props", {}).get("dangerous"):
                findings.append(make_finding(
                    finding_id  = self._next_fid(),
                    category    = "DANGEROUS_CALL",
                    description = (
                        f"Dangerous function '{node['name']}' called "
                        f"at line {node.get('line', 'unknown')}."
                    ),
                    line        = node.get("line"),
                    severity    = "high",
                    node_id     = node["id"]
                ))

        # Secret flag findings
        for node in self.nodes:
            if node.get("type") == "secret_flag":
                findings.append(make_finding(
                    finding_id  = self._next_fid(),
                    category    = "SECRET_EXPOSURE",
                    description = (
                        f"Potential secret or credential assigned to "
                        f"'{node['name']}' at line {node.get('line', 'unknown')}."
                    ),
                    line        = node.get("line"),
                    severity    = "medium",
                    node_id     = node["id"]
                ))

        return findings


# ---------------------------------------------------------------------------
# Analysis engine -- entry point
# ---------------------------------------------------------------------------

class AnalysisEngine:
    """
    MOD-02 entry point.
    Accepts a MOD-01 IR dict, runs taint analysis + CFG construction,
    and returns a structured analysis report.
    """

    def analyze(self, ir):
        language = ir.get("language", "unknown")
        nodes    = ir.get("nodes", [])
        edges    = ir.get("edges", [])

        graph   = IRGraph(nodes, edges)
        taint   = TaintAnalyzer(graph, language)
        cfg_b   = CFGBuilder(graph)
        taint_flows = taint.analyze()
        cfg         = cfg_b.build()
        findings    = FindingGenerator(taint_flows, nodes, language).generate()

        critical = sum(1 for f in findings if f["severity"] == "critical")
        high     = sum(1 for f in findings if f["severity"] == "high")
        medium   = sum(1 for f in findings if f["severity"] == "medium")

        return {
            "file":        ir.get("file", "unknown"),
            "language":    language,
            "taint_flows": taint_flows,
            "cfg":         cfg,
            "findings":    findings,
            "metadata": {
                "taint_flow_count":   len(taint_flows),
                "cfg_function_count": len(cfg),
                "finding_count":      len(findings),
                "severity_summary": {
                    "critical": critical,
                    "high":     high,
                    "medium":   medium
                },
                "analyzer": "AnalysisEngine v0.1.0",
                "analyzed_at": datetime.now(timezone.utc).isoformat()
            }
        }

    def export_json(self, report, output_path):
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[MOD-02] Analysis report exported to {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python analysis_engine.py <ir_json_file>")
        sys.exit(1)

    with open(sys.argv[1], "r", encoding="utf-8") as f:
        ir = json.load(f)

    engine = AnalysisEngine()
    report = engine.analyze(ir)
    m      = report["metadata"]

    print(f"\n[MOD-02] MISTCODER Static Analysis Engine v0.1.0")
    print(f"[MOD-02] File     : {report['file']}")
    print(f"[MOD-02] Language : {report['language']}")
    print("-" * 60)
    print(f"  Taint flows   : {m['taint_flow_count']}")
    print(f"  CFG functions : {m['cfg_function_count']}")
    print(f"  Findings      : {m['finding_count']}")
    print(f"  Critical      : {m['severity_summary']['critical']}")
    print(f"  High          : {m['severity_summary']['high']}")
    print(f"  Medium        : {m['severity_summary']['medium']}")
    print("-" * 60)

    for finding in report["findings"]:
        print(f"  [{finding['severity'].upper():8s}] "
              f"{finding['id']} -- {finding['category']}")
        print(f"             {finding['description']}")

    print("-" * 60)
    print("[MOD-02] Analysis complete.")
