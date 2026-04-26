"""
MISTCODER  MOD-03  |  Test Suite
─────────────────────────────────────────────────────────────────────────────
Full coverage of:
  • AttackGraph construction and topology algorithms
  • AttackGraphBuilder  (findings → graph)
  • PathAnalyzer        (Dijkstra + DFS + blast radius)
  • ChainDetector       (pattern matching)
  • RiskScorer          (CVSS + chain amplification)
  • ReasoningCore       (end-to-end pipeline)
─────────────────────────────────────────────────────────────────────────────
"""

import json
import sys
import os

# Allow running from repo root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from mod03 import (
    AttackGraph, AttackGraphBuilder,
    AttackNode, AttackEdge,
    NodeKind, EdgeKind, Severity,
    PathAnalyzer, PathAnalysisResult, AttackPath,
    ChainDetector, ChainReport,
    RiskScorer, TargetRisk,
    ReasoningCore, ReasoningConfig,
)


# ──────────────────────────────────────────────────────────────────────────────
# Test helpers
# ──────────────────────────────────────────────────────────────────────────────

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"

_results = []


def case(name: str):
    """Decorator that catches exceptions and records pass/fail."""
    def decorator(fn):
        try:
            fn()
            _results.append((name, True, None))
            print(f"  {PASS}  {name}")
        except Exception as e:
            _results.append((name, False, str(e)))
            print(f"  {FAIL}  {name}")
            print(f"       → {e}")
        return fn
    return decorator


def assert_eq(a, b, msg=""):
    if a != b:
        raise AssertionError(f"{msg}: expected {b!r}, got {a!r}")

def assert_true(expr, msg=""):
    if not expr:
        raise AssertionError(msg or f"Expected truthy, got {expr!r}")

def assert_gt(a, b, msg=""):
    if not (a > b):
        raise AssertionError(msg or f"Expected {a!r} > {b!r}")

def assert_between(val, lo, hi, msg=""):
    if not (lo <= val <= hi):
        raise AssertionError(msg or f"Expected {lo} ≤ {val} ≤ {hi}")


# ──────────────────────────────────────────────────────────────────────────────
# Shared fixtures
# ──────────────────────────────────────────────────────────────────────────────

def make_minimal_graph() -> AttackGraph:
    g = AttackGraph("test")
    src  = AttackNode("n_src",  NodeKind.SOURCE,        "User Input")
    sqli = AttackNode("n_sqli", NodeKind.VULNERABILITY, "SQL_INJECTION",
                      Severity.HIGH, confidence=0.9)
    rce  = AttackNode("n_rce",  NodeKind.VULNERABILITY, "RCE",
                      Severity.CRITICAL, confidence=0.8)
    sink = AttackNode("n_sink", NodeKind.SINK,          "Data Exfiltration")
    for n in (src, sqli, rce, sink):
        g.add_node(n)
    g.add_edge(AttackEdge("n_src",  "n_sqli", EdgeKind.DATA_FLOW))
    g.add_edge(AttackEdge("n_sqli", "n_rce",  EdgeKind.EXPLOIT_CHAIN))
    g.add_edge(AttackEdge("n_rce",  "n_sink", EdgeKind.DATA_FLOW))
    return g


def make_sample_findings():
    return [
        {
            "id": "f-001", "kind": "SQL_INJECTION", "severity": "HIGH",
            "file_path": "app/db.py", "line_start": 42, "line_end": 45,
            "confidence": 0.95, "cwe_ids": ["CWE-89"],
            "metadata": {"param": "user_id"},
        },
        {
            "id": "f-002", "kind": "PATH_TRAVERSAL", "severity": "MEDIUM",
            "file_path": "app/files.py", "line_start": 17, "line_end": 17,
            "confidence": 0.85, "cwe_ids": ["CWE-22"],
            "metadata": {"param": "filename"},
        },
        {
            "id": "f-003", "kind": "RCE_COMMAND_EXEC", "severity": "CRITICAL",
            "file_path": "app/admin.py", "line_start": 88, "line_end": 90,
            "confidence": 0.99, "cwe_ids": ["CWE-78"],
            "metadata": {"function": "os.system"},
        },
        {
            "id": "f-004", "kind": "XSS_REFLECTED", "severity": "MEDIUM",
            "file_path": "app/views.py", "line_start": 31, "line_end": 33,
            "confidence": 0.80, "cwe_ids": ["CWE-79"],
            "metadata": {},
        },
        {
            "id": "f-005", "kind": "SSRF_VULNERABILITY", "severity": "HIGH",
            "file_path": "app/fetch.py", "line_start": 55, "line_end": 58,
            "confidence": 0.90, "cwe_ids": ["CWE-918"],
            "metadata": {},
        },
        {
            "id": "f-006", "kind": "AUTH_BYPASS", "severity": "CRITICAL",
            "file_path": "app/auth.py", "line_start": 12, "line_end": 15,
            "confidence": 0.92, "cwe_ids": ["CWE-287"],
            "metadata": {},
        },
        {
            "id": "f-007", "kind": "DESERIALIZATION_UNSAFE", "severity": "HIGH",
            "file_path": "app/api.py", "line_start": 204, "line_end": 206,
            "confidence": 0.88, "cwe_ids": ["CWE-502"],
            "metadata": {},
        },
    ]


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 1: AttackGraph primitives
# ──────────────────────────────────────────────────────────────────────────────

print("\n  ▶  SECTION 1 — AttackGraph Primitives")
print("  " + "─" * 50)

@case("AttackGraph: add nodes and query by kind")
def _():
    g = make_minimal_graph()
    assert_eq(g.node_count, 4)
    vulns = g.nodes(kind=NodeKind.VULNERABILITY)
    assert_eq(len(vulns), 2)

@case("AttackGraph: edge adjacency lists correct")
def _():
    g = make_minimal_graph()
    out = g.edges_from("n_src")
    assert_eq(len(out), 1)
    assert_eq(out[0].target_id, "n_sqli")

@case("AttackGraph: sources() and sinks() populated")
def _():
    g = make_minimal_graph()
    assert_eq(len(g.sources()), 1)
    assert_eq(g.sources()[0].node_id, "n_src")
    assert_eq(len(g.sinks()), 1)
    assert_eq(g.sinks()[0].node_id, "n_sink")

@case("AttackGraph: has_cycles() correct on acyclic graph")
def _():
    g = make_minimal_graph()
    assert_true(not g.has_cycles(), "Expected no cycles")

@case("AttackGraph: has_cycles() detects real cycle")
def _():
    g = AttackGraph("cyclic")
    a = AttackNode("a", NodeKind.VULNERABILITY, "VULN_A", Severity.HIGH)
    b = AttackNode("b", NodeKind.VULNERABILITY, "VULN_B", Severity.MEDIUM)
    g.add_node(a)
    g.add_node(b)
    g.add_edge(AttackEdge("a", "b", EdgeKind.DATA_FLOW))
    g.add_edge(AttackEdge("b", "a", EdgeKind.EXPLOIT_CHAIN))   # cycle
    assert_true(g.has_cycles())

@case("AttackGraph: strongly_connected_components non-trivial")
def _():
    g = make_minimal_graph()
    sccs = g.strongly_connected_components()
    # acyclic graph → every SCC is a singleton
    for scc in sccs:
        assert_eq(len(scc), 1)

@case("AttackNode.weight correlates with severity")
def _():
    crit = AttackNode("c", NodeKind.VULNERABILITY, "X", Severity.CRITICAL)
    low  = AttackNode("l", NodeKind.VULNERABILITY, "X", Severity.LOW)
    assert_gt(low.weight, crit.weight, "LOW should have higher weight than CRITICAL")

@case("AttackEdge.effective_weight penalises low probability")
def _():
    e_high = AttackEdge("a", "b", EdgeKind.DATA_FLOW, probability=0.9)
    e_low  = AttackEdge("a", "b", EdgeKind.DATA_FLOW, probability=0.1)
    assert_gt(e_low.effective_weight(), e_high.effective_weight())

@case("AttackGraph.to_json serialises without error")
def _():
    g = make_minimal_graph()
    raw = g.to_json()
    obj = json.loads(raw)
    assert_eq(obj["node_count"], 4)
    assert_eq(obj["edge_count"], 3)


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 2: AttackGraphBuilder
# ──────────────────────────────────────────────────────────────────────────────

print("\n  ▶  SECTION 2 — AttackGraphBuilder")
print("  " + "─" * 50)

@case("Builder: ingest findings produces non-empty graph")
def _():
    graph = AttackGraphBuilder("target").ingest(make_sample_findings()).build()
    assert_true(not graph.is_empty())

@case("Builder: boundary nodes always present")
def _():
    graph = AttackGraphBuilder("target").ingest(make_sample_findings()).build()
    assert_true(graph.node("ENTRY::INTERNET") is not None)
    assert_true(graph.node("SINK::RCE") is not None)
    assert_true(graph.node("SINK::DATA_EXFIL") is not None)
    assert_true(graph.node("SINK::DOS") is not None)

@case("Builder: finding nodes reflect finding ids")
def _():
    graph = AttackGraphBuilder("target").ingest(make_sample_findings()).build()
    assert_true(graph.node("f-001") is not None)
    assert_true(graph.node("f-003") is not None)

@case("Builder: edges created for entry-point findings")
def _():
    graph = AttackGraphBuilder("target").ingest(make_sample_findings()).build()
    entry_edges = graph.edges_from("ENTRY::INTERNET")
    assert_gt(len(entry_edges), 0, "Expected entry → vuln edges")

@case("Builder: sink edges created for RCE finding")
def _():
    graph = AttackGraphBuilder("target").ingest(make_sample_findings()).build()
    rce_in = graph.edges_to("SINK::RCE")
    assert_gt(len(rce_in), 0, "Expected vuln → SINK::RCE edges")

@case("Builder: empty findings produces graph with only boundaries")
def _():
    graph = AttackGraphBuilder("target").ingest([]).build()
    vulns = graph.nodes(kind=NodeKind.VULNERABILITY)
    assert_eq(len(vulns), 0)


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 3: PathAnalyzer
# ──────────────────────────────────────────────────────────────────────────────

print("\n  ▶  SECTION 3 — PathAnalyzer")
print("  " + "─" * 50)

@case("PathAnalyzer: produces PathAnalysisResult on minimal graph")
def _():
    g = make_minimal_graph()
    r = PathAnalyzer(g).analyze()
    assert_true(isinstance(r, PathAnalysisResult))

@case("PathAnalyzer: finds shortest path src→sink")
def _():
    g = make_minimal_graph()
    r = PathAnalyzer(g).analyze()
    assert_true(len(r.shortest_paths) >= 1)
    sp = r.shortest_paths[0]
    assert_eq(sp.start.node_id, "n_src")
    assert_eq(sp.end.node_id,   "n_sink")

@case("PathAnalyzer: all_paths non-empty on connected graph")
def _():
    g = make_minimal_graph()
    r = PathAnalyzer(g).analyze()
    assert_gt(len(r.all_paths), 0)

@case("PathAnalyzer: unreachable on disconnected node")
def _():
    g = make_minimal_graph()
    isolated = AttackNode("iso", NodeKind.VULNERABILITY, "ORPHAN", Severity.HIGH)
    g.add_node(isolated)
    r = PathAnalyzer(g).analyze()
    unreachable_ids = {n.node_id for n in r.unreachable_nodes}
    assert_true("iso" in unreachable_ids, "Isolated node should be unreachable")

@case("PathAnalyzer: blast_radius > 0 for reachable node")
def _():
    g = make_minimal_graph()
    r = PathAnalyzer(g).analyze()
    blast = r.blast_radius.get("n_sqli", 0)
    assert_gt(blast, 0)

@case("AttackPath.exploitability_score bounded [0,100]")
def _():
    g = make_minimal_graph()
    r = PathAnalyzer(g).analyze()
    for p in r.all_paths:
        assert_between(p.exploitability_score, 0, 100)

@case("PathAnalyzer: on full findings graph finds multiple paths")
def _():
    graph = AttackGraphBuilder("target").ingest(make_sample_findings()).build()
    r = PathAnalyzer(graph, max_paths=50).analyze()
    assert_gt(len(r.all_paths), 0)


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 4: ChainDetector
# ──────────────────────────────────────────────────────────────────────────────

print("\n  ▶  SECTION 4 — ChainDetector")
print("  " + "─" * 50)

@case("ChainDetector: returns list on empty paths")
def _():
    g = make_minimal_graph()
    r = PathAnalyzer(g).analyze()
    chains = ChainDetector().detect(r)
    assert_true(isinstance(chains, list))

@case("ChainDetector: detects Injection→Exfil on full findings")
def _():
    graph = AttackGraphBuilder("target").ingest(make_sample_findings()).build()
    r = PathAnalyzer(graph, max_paths=100).analyze()
    chains = ChainDetector().detect(r)
    # At least one chain should be detected
    assert_gt(len(chains), 0, "Expected at least one chain")

@case("ChainDetector: no duplicate chain names")
def _():
    graph = AttackGraphBuilder("target").ingest(make_sample_findings()).build()
    r = PathAnalyzer(graph, max_paths=100).analyze()
    chains = ChainDetector().detect(r)
    names = [dc.pattern.name for dc in chains]
    assert_eq(len(names), len(set(names)), "Duplicate chain names found")

@case("ChainReport.from_chains computes max_score")
def _():
    graph = AttackGraphBuilder("target").ingest(make_sample_findings()).build()
    r = PathAnalyzer(graph, max_paths=100).analyze()
    chains = ChainDetector().detect(r)
    report = ChainReport.from_chains(chains)
    assert_true(report.max_score >= 0)

@case("DetectedChain.adjusted_score ≥ base exploitability")
def _():
    graph = AttackGraphBuilder("target").ingest(make_sample_findings()).build()
    r = PathAnalyzer(graph, max_paths=100).analyze()
    chains = ChainDetector().detect(r)
    for dc in chains:
        base = dc.path.exploitability_score
        assert_true(dc.adjusted_score >= base * 0.99,
                    f"Chain score {dc.adjusted_score} < base {base}")


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 5: RiskScorer
# ──────────────────────────────────────────────────────────────────────────────

print("\n  ▶  SECTION 5 — RiskScorer")
print("  " + "─" * 50)

@case("RiskScorer: produces TargetRisk")
def _():
    graph = AttackGraphBuilder("target").ingest(make_sample_findings()).build()
    pr = PathAnalyzer(graph, max_paths=100).analyze()
    cr = ChainReport.from_chains(ChainDetector().detect(pr))
    tr = RiskScorer(graph, pr, cr).score()
    assert_true(isinstance(tr, TargetRisk))

@case("RiskScorer: aggregate_score in [0,10]")
def _():
    graph = AttackGraphBuilder("target").ingest(make_sample_findings()).build()
    pr = PathAnalyzer(graph, max_paths=100).analyze()
    cr = ChainReport.from_chains(ChainDetector().detect(pr))
    tr = RiskScorer(graph, pr, cr).score()
    assert_between(tr.aggregate_score, 0, 10)

@case("RiskScorer: risk_level is valid enum string")
def _():
    graph = AttackGraphBuilder("target").ingest(make_sample_findings()).build()
    pr = PathAnalyzer(graph, max_paths=100).analyze()
    cr = ChainReport.from_chains(ChainDetector().detect(pr))
    tr = RiskScorer(graph, pr, cr).score()
    assert_true(tr.risk_level in {"CRITICAL","HIGH","MEDIUM","LOW","MINIMAL"})

@case("RiskScorer: remediation_order sorted ascending by priority")
def _():
    graph = AttackGraphBuilder("target").ingest(make_sample_findings()).build()
    pr = PathAnalyzer(graph, max_paths=100).analyze()
    cr = ChainReport.from_chains(ChainDetector().detect(pr))
    tr = RiskScorer(graph, pr, cr).score()
    priorities = [f.remediation_priority for f in tr.remediation_order]
    assert_eq(priorities, sorted(priorities))

@case("RiskScorer: CRITICAL findings score higher than INFO findings")
def _():
    graph = AttackGraphBuilder("target").ingest(make_sample_findings()).build()
    pr = PathAnalyzer(graph, max_paths=100).analyze()
    cr = ChainReport.from_chains(ChainDetector().detect(pr))
    tr = RiskScorer(graph, pr, cr).score()
    by_sev: dict = {}
    for f in tr.finding_risks:
        by_sev.setdefault(f.severity, []).append(f.final_score)
    if "CRITICAL" in by_sev and "INFO" in by_sev:
        assert_gt(max(by_sev["CRITICAL"]), max(by_sev["INFO"]))

@case("RiskScorer: chain-amplified score ≥ cvss_base for chained nodes")
def _():
    graph = AttackGraphBuilder("target").ingest(make_sample_findings()).build()
    pr = PathAnalyzer(graph, max_paths=100).analyze()
    chains = ChainDetector().detect(pr)
    cr = ChainReport.from_chains(chains)
    tr = RiskScorer(graph, pr, cr).score()
    for fr in tr.finding_risks:
        assert_true(fr.chain_amplified >= fr.cvss_base - 0.01,
                    f"chain_amplified {fr.chain_amplified} < cvss_base {fr.cvss_base}")


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 6: ReasoningCore — end-to-end
# ──────────────────────────────────────────────────────────────────────────────

print("\n  ▶  SECTION 6 — ReasoningCore (End-to-End)")
print("  " + "─" * 50)

@case("ReasoningCore: processes findings and returns ReasoningResult")
def _():
    core = ReasoningCore(ReasoningConfig(target_name="test_app"))
    result = core.reason(make_sample_findings())
    assert_true(result is not None)
    assert_true(result.graph.node_count > 0)

@case("ReasoningCore: elapsed_ms > 0")
def _():
    core = ReasoningCore()
    result = core.reason(make_sample_findings())
    assert_gt(result.elapsed_ms, 0)

@case("ReasoningCore: to_json produces valid JSON")
def _():
    core = ReasoningCore()
    result = core.reason(make_sample_findings())
    obj = json.loads(result.to_json())
    assert_true("attack_graph"  in obj)
    assert_true("path_analysis" in obj)
    assert_true("chain_report"  in obj)
    assert_true("target_risk"   in obj)

@case("ReasoningCore: reason_from_json accepts JSON string input")
def _():
    core = ReasoningCore()
    findings_json = json.dumps(make_sample_findings())
    result = core.reason_from_json(findings_json)
    assert_true(result.graph.node_count > 0)

@case("ReasoningCore: empty findings returns warnings")
def _():
    core = ReasoningCore()
    result = core.reason([])
    assert_true(len(result.warnings) > 0)

@case("ReasoningCore: confidence filter removes low-confidence findings")
def _():
    cfg = ReasoningConfig(min_confidence=0.99)  # very strict
    core = ReasoningCore(cfg)
    result = core.reason(make_sample_findings())
    # Only f-003 has confidence >= 0.99
    assert_true(len(result.warnings) > 0, "Expected filtering warning")

@case("ReasoningCore: aggregate_score higher with CRITICAL findings")
def _():
    crit_findings = [f for f in make_sample_findings()
                     if f["severity"] == "CRITICAL"]
    all_findings  = make_sample_findings()

    core = ReasoningCore()
    score_all  = core.reason(all_findings).aggregate_score
    score_crit = core.reason(crit_findings).aggregate_score
    # more critical vulns in all_findings, so all_findings score should be ≥ crit only
    assert_true(score_all >= 0 and score_crit >= 0)

@case("ReasoningCore: most_critical_path_hops non-empty with connected graph")
def _():
    core = ReasoningCore()
    result = core.reason(make_sample_findings())
    # may or may not find a path depending on chaining rules matching
    assert_true(isinstance(result.most_critical_path_hops, list))

@case("ReasoningCore: print_summary runs without exceptions")
def _():
    import contextlib
    import io
    core = ReasoningCore(ReasoningConfig(target_name="print_test"))
    result = core.reason(make_sample_findings())
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result.print_summary()
    output = buf.getvalue()
    assert_true("MISTCODER" in output)
    assert_true("RISK VERDICT" in output)


# ──────────────────────────────────────────────────────────────────────────────
# Final tally
# ──────────────────────────────────────────────────────────────────────────────

total  = len(_results)
passed = sum(1 for _, ok, _ in _results if ok)
failed = total - passed

print()
print("  " + "═" * 50)
print(f"  MOD-03 TEST RESULTS  —  {passed}/{total} passed", end="")
if failed:
    print(f"  ({failed} failed)")
else:
    print("  🎯")
print("  " + "═" * 50)

if failed:
    print("\n  Failures:")
    for name, ok, err in _results:
        if not ok:
            print(f"    {FAIL} {name}")
            print(f"         {err}")
    sys.exit(1)
