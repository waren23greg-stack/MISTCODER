"""
MISTCODER  MOD-03  |  Attack Graph Engine
─────────────────────────────────────────────────────────────────────────────
Constructs a directed, weighted property graph where:

  • Nodes  = vulnerabilities, data sources, trust boundaries, sinks
  • Edges  = exploitability relationships and data-flow arcs
  • Weight = composite exploitability score  (lower = easier to traverse)

The graph is then handed to ChainDetector and PathAnalyzer for reasoning.
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple


# ──────────────────────────────────────────────────────────────────────────────
# Domain enumerations
# ──────────────────────────────────────────────────────────────────────────────

class NodeKind(str, Enum):
    SOURCE        = "SOURCE"        # untrusted input entry-point
    VULNERABILITY = "VULNERABILITY" # detected weakness
    PROPAGATION   = "PROPAGATION"   # taint travels through this node
    SINK          = "SINK"          # dangerous operation / impact point
    BOUNDARY      = "BOUNDARY"      # trust-boundary crossing


class EdgeKind(str, Enum):
    DATA_FLOW     = "DATA_FLOW"     # taint propagation
    EXPLOIT_CHAIN = "EXPLOIT_CHAIN" # one vuln enables another
    AUTH_BYPASS   = "AUTH_BYPASS"   # bypasses an auth check
    PRIVILEGE_ESC = "PRIVILEGE_ESC" # elevates privilege context
    LATERAL_MOVE  = "LATERAL_MOVE"  # moves to another component


class Severity(str, Enum):
    CRITICAL = "CRITICAL"   # CVSS 9.0–10.0
    HIGH     = "HIGH"       # CVSS 7.0–8.9
    MEDIUM   = "MEDIUM"     # CVSS 4.0–6.9
    LOW      = "LOW"        # CVSS 0.1–3.9
    INFO     = "INFO"       # Informational


SEVERITY_WEIGHT: Dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH":     2.5,
    "MEDIUM":   5.0,
    "LOW":      8.0,
    "INFO":     10.0,
}


# ──────────────────────────────────────────────────────────────────────────────
# Graph primitives
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class AttackNode:
    """A single vertex in the attack graph."""

    node_id:      str
    kind:         NodeKind
    label:        str
    severity:     Severity            = Severity.INFO
    cwe_ids:      List[str]           = field(default_factory=list)
    file_path:    Optional[str]       = None
    line_start:   Optional[int]       = None
    line_end:     Optional[int]       = None
    confidence:   float               = 1.0        # 0.0 – 1.0
    properties:   Dict[str, Any]      = field(default_factory=dict)

    # runtime – filled by PathAnalyzer
    reachability_score: float         = 0.0
    impact_score:       float         = 0.0

    @property
    def weight(self) -> float:
        """Lower weight = easier to exploit / traverse."""
        base  = SEVERITY_WEIGHT.get(self.severity.value, 5.0)
        conf  = max(0.1, self.confidence)           # avoid division by zero
        return base / conf

    def __hash__(self)  -> int:  return hash(self.node_id)
    def __eq__(self, o) -> bool: return isinstance(o, AttackNode) and self.node_id == o.node_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id":    self.node_id,
            "kind":       self.kind.value,
            "label":      self.label,
            "severity":   self.severity.value,
            "cwe_ids":    self.cwe_ids,
            "file_path":  self.file_path,
            "line_start": self.line_start,
            "line_end":   self.line_end,
            "confidence": self.confidence,
            "weight":     self.weight,
            "reachability_score": self.reachability_score,
            "impact_score":       self.impact_score,
            "properties": self.properties,
        }


@dataclass
class AttackEdge:
    """A directed edge connecting two AttackNodes."""

    source_id:  str
    target_id:  str
    kind:       EdgeKind
    label:      str               = ""
    weight:     float             = 1.0   # traversal cost
    probability: float            = 1.0   # 0.0 – 1.0 likelihood of this transition
    conditions:  List[str]        = field(default_factory=list)
    properties:  Dict[str, Any]   = field(default_factory=dict)

    @property
    def edge_id(self) -> str:
        raw = f"{self.source_id}→{self.target_id}:{self.kind.value}"
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    def effective_weight(self) -> float:
        """Penalise low-probability edges so Dijkstra prefers reliable paths."""
        p = max(0.01, self.probability)
        return self.weight / p

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id":    self.edge_id,
            "source_id":  self.source_id,
            "target_id":  self.target_id,
            "kind":       self.kind.value,
            "label":      self.label,
            "weight":     self.weight,
            "probability": self.probability,
            "conditions": self.conditions,
        }


# ──────────────────────────────────────────────────────────────────────────────
# The Attack Graph
# ──────────────────────────────────────────────────────────────────────────────

class AttackGraph:
    """
    Directed, weighted property graph.

    Internally uses adjacency lists for O(1) neighbour lookup.
    Supports multi-edges (same src→dst, different EdgeKind).
    """

    def __init__(self, name: str = "unnamed") -> None:
        self.name            = name
        self._nodes:  Dict[str, AttackNode]       = {}
        self._out:    Dict[str, List[AttackEdge]] = {}   # src → edges
        self._in:     Dict[str, List[AttackEdge]] = {}   # dst → edges
        self._sources: Set[str]                   = set()
        self._sinks:   Set[str]                   = set()

    # ── Mutation ─────────────────────────────────────────────────────────────

    def add_node(self, node: AttackNode) -> "AttackGraph":
        self._nodes[node.node_id] = node
        self._out.setdefault(node.node_id, [])
        self._in.setdefault(node.node_id, [])
        if node.kind == NodeKind.SOURCE:
            self._sources.add(node.node_id)
        if node.kind == NodeKind.SINK:
            self._sinks.add(node.node_id)
        return self

    def add_edge(self, edge: AttackEdge) -> "AttackGraph":
        if edge.source_id not in self._nodes:
            raise ValueError(f"Source node '{edge.source_id}' not in graph")
        if edge.target_id not in self._nodes:
            raise ValueError(f"Target node '{edge.target_id}' not in graph")
        self._out[edge.source_id].append(edge)
        self._in[edge.target_id].append(edge)
        return self

    # ── Queries ───────────────────────────────────────────────────────────────

    def node(self, node_id: str) -> Optional[AttackNode]:
        return self._nodes.get(node_id)

    def nodes(self, kind: Optional[NodeKind] = None) -> List[AttackNode]:
        ns = list(self._nodes.values())
        if kind:
            ns = [n for n in ns if n.kind == kind]
        return ns

    def edges_from(self, node_id: str) -> List[AttackEdge]:
        return self._out.get(node_id, [])

    def edges_to(self, node_id: str) -> List[AttackEdge]:
        return self._in.get(node_id, [])

    def all_edges(self) -> Iterator[AttackEdge]:
        for edges in self._out.values():
            yield from edges

    def sources(self) -> List[AttackNode]:
        return [self._nodes[nid] for nid in self._sources if nid in self._nodes]

    def sinks(self) -> List[AttackNode]:
        return [self._nodes[nid] for nid in self._sinks if nid in self._nodes]

    def successors(self, node_id: str) -> List[AttackNode]:
        return [self._nodes[e.target_id] for e in self._out.get(node_id, [])
                if e.target_id in self._nodes]

    def predecessors(self, node_id: str) -> List[AttackNode]:
        return [self._nodes[e.source_id] for e in self._in.get(node_id, [])
                if e.source_id in self._nodes]

    # ── Graph-level properties ────────────────────────────────────────────────

    @property
    def node_count(self) -> int: return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return sum(len(es) for es in self._out.values())

    def is_empty(self) -> bool: return self.node_count == 0

    def has_cycles(self) -> bool:
        """DFS-based cycle detection."""
        WHITE, GRAY, BLACK = 0, 1, 2
        color: Dict[str, int] = {nid: WHITE for nid in self._nodes}

        def dfs(nid: str) -> bool:
            color[nid] = GRAY
            for succ in self.successors(nid):
                if color[succ.node_id] == GRAY:
                    return True
                if color[succ.node_id] == WHITE and dfs(succ.node_id):
                    return True
            color[nid] = BLACK
            return False

        return any(dfs(nid) for nid in self._nodes if color[nid] == WHITE)

    def strongly_connected_components(self) -> List[List[str]]:
        """Kosaraju's algorithm – identifies vulnerability clusters."""
        order: List[str] = []
        visited: Set[str] = set()

        def dfs1(nid: str) -> None:
            visited.add(nid)
            for succ in self.successors(nid):
                if succ.node_id not in visited:
                    dfs1(succ.node_id)
            order.append(nid)

        def dfs2(nid: str, comp: List[str]) -> None:
            visited.add(nid)
            comp.append(nid)
            for pred in self.predecessors(nid):
                if pred.node_id not in visited:
                    dfs2(pred.node_id, comp)

        for nid in list(self._nodes.keys()):
            if nid not in visited:
                dfs1(nid)

        visited.clear()
        components: List[List[str]] = []
        for nid in reversed(order):
            if nid not in visited:
                comp: List[str] = []
                dfs2(nid, comp)
                components.append(comp)
        return components

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name":       self.name,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "has_cycles": self.has_cycles(),
            "nodes":      [n.to_dict() for n in self._nodes.values()],
            "edges":      [e.to_dict() for e in self.all_edges()],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def __repr__(self) -> str:
        return (f"<AttackGraph name={self.name!r} "
                f"nodes={self.node_count} edges={self.edge_count}>")


# ──────────────────────────────────────────────────────────────────────────────
# Graph Builder  –  translates MOD-02 findings → AttackGraph
# ──────────────────────────────────────────────────────────────────────────────

class AttackGraphBuilder:
    """
    Translates MOD-02 Analysis Engine output into an AttackGraph.

    Findings are expected as dicts with at minimum:
        {
          "id":         str,
          "kind":       str,          # e.g. "SQL_INJECTION"
          "severity":   str,          # CRITICAL | HIGH | MEDIUM | LOW | INFO
          "file_path":  str,
          "line_start": int,
          "confidence": float,
          "cwe_ids":    List[str],
          "metadata":   Dict[str, Any]
        }
    """

    # Maps finding kind strings to edge relationships
    CHAINING_RULES: List[Tuple[str, str, EdgeKind, float]] = [
        # (from_pattern, to_pattern, edge_kind, base_probability)
        ("AUTH",        "INJECTION",    EdgeKind.EXPLOIT_CHAIN, 0.85),
        ("INJECTION",   "RCE",          EdgeKind.EXPLOIT_CHAIN, 0.80),
        ("INJECTION",   "DATA_EXFIL",   EdgeKind.DATA_FLOW,     0.75),
        ("PATH_TRAV",   "FILE_READ",    EdgeKind.DATA_FLOW,     0.90),
        ("FILE_READ",   "CREDENTIAL",   EdgeKind.DATA_FLOW,     0.70),
        ("CREDENTIAL",  "PRIV_ESC",     EdgeKind.PRIVILEGE_ESC, 0.65),
        ("PRIV_ESC",    "LATERAL",      EdgeKind.LATERAL_MOVE,  0.60),
        ("SSRF",        "INTERNAL_NET", EdgeKind.LATERAL_MOVE,  0.75),
        ("DESERIAL",    "RCE",          EdgeKind.EXPLOIT_CHAIN, 0.88),
        ("XSS",         "SESSION",      EdgeKind.EXPLOIT_CHAIN, 0.70),
        ("SESSION",     "AUTH",         EdgeKind.AUTH_BYPASS,   0.65),
    ]

    def __init__(self, target_name: str = "target") -> None:
        self._target_name = target_name
        self._graph       = AttackGraph(name=target_name)
        self._findings:   List[Dict[str, Any]] = []

    def ingest(self, findings: List[Dict[str, Any]]) -> "AttackGraphBuilder":
        self._findings.extend(findings)
        return self

    def build(self) -> AttackGraph:
        self._add_boundary_nodes()
        self._findings_to_nodes()
        self._apply_chaining_rules()
        self._connect_sources_to_first_hop()
        self._connect_last_hop_to_sinks()
        return self._graph

    # ── private helpers ───────────────────────────────────────────────────────

    def _add_boundary_nodes(self) -> None:
        source = AttackNode(
            node_id  = "ENTRY::INTERNET",
            kind     = NodeKind.SOURCE,
            label    = "Untrusted Internet Input",
            severity = Severity.INFO,
        )
        sink_rce = AttackNode(
            node_id  = "SINK::RCE",
            kind     = NodeKind.SINK,
            label    = "Remote Code Execution",
            severity = Severity.CRITICAL,
        )
        sink_exfil = AttackNode(
            node_id  = "SINK::DATA_EXFIL",
            kind     = NodeKind.SINK,
            label    = "Sensitive Data Exfiltration",
            severity = Severity.CRITICAL,
        )
        sink_dos = AttackNode(
            node_id  = "SINK::DOS",
            kind     = NodeKind.SINK,
            label    = "Denial of Service",
            severity = Severity.HIGH,
        )
        for n in (source, sink_rce, sink_exfil, sink_dos):
            self._graph.add_node(n)

    def _findings_to_nodes(self) -> None:
        for f in self._findings:
            sev_str = f.get("severity", "INFO").upper()
            try:
                sev = Severity[sev_str]
            except KeyError:
                sev = Severity.INFO

            node = AttackNode(
                node_id    = f["id"],
                kind       = NodeKind.VULNERABILITY,
                label      = f.get("kind", "UNKNOWN"),
                severity   = sev,
                cwe_ids    = f.get("cwe_ids", []),
                file_path  = f.get("file_path"),
                line_start = f.get("line_start"),
                line_end   = f.get("line_end"),
                confidence = f.get("confidence", 1.0),
                properties = f.get("metadata", {}),
            )
            self._graph.add_node(node)

    def _apply_chaining_rules(self) -> None:
        vuln_nodes = self._graph.nodes(kind=NodeKind.VULNERABILITY)

        for a in vuln_nodes:
            for b in vuln_nodes:
                if a.node_id == b.node_id:
                    continue
                for from_pat, to_pat, ek, prob in self.CHAINING_RULES:
                    if from_pat in a.label.upper() and to_pat in b.label.upper():
                        edge = AttackEdge(
                            source_id   = a.node_id,
                            target_id   = b.node_id,
                            kind        = ek,
                            label       = f"{a.label} → {b.label}",
                            weight      = (a.weight + b.weight) / 2,
                            probability = prob * a.confidence * b.confidence,
                        )
                        self._graph.add_edge(edge)

    def _connect_sources_to_first_hop(self) -> None:
        entry = self._graph.node("ENTRY::INTERNET")
        if not entry:
            return
        # First-hop: high-severity vulns that are likely entry points
        entry_patterns = {"INJECTION", "XSS", "SSRF", "PATH_TRAV", "DESERIAL",
                          "UPLOAD", "AUTH", "IDOR"}
        for vnode in self._graph.nodes(kind=NodeKind.VULNERABILITY):
            if any(p in vnode.label.upper() for p in entry_patterns):
                edge = AttackEdge(
                    source_id   = "ENTRY::INTERNET",
                    target_id   = vnode.node_id,
                    kind        = EdgeKind.DATA_FLOW,
                    label       = f"attacker reaches {vnode.label}",
                    weight      = vnode.weight,
                    probability = vnode.confidence,
                )
                self._graph.add_edge(edge)

    def _connect_last_hop_to_sinks(self) -> None:
        sink_map = {
            "RCE":       "SINK::RCE",
            "COMMAND":   "SINK::RCE",
            "EXEC":      "SINK::RCE",
            "EXFIL":     "SINK::DATA_EXFIL",
            "INJECTION": "SINK::DATA_EXFIL",
            "SSRF":      "SINK::DATA_EXFIL",
            "DOS":       "SINK::DOS",
            "REDOS":     "SINK::DOS",
        }
        for vnode in self._graph.nodes(kind=NodeKind.VULNERABILITY):
            for pattern, sink_id in sink_map.items():
                if pattern in vnode.label.upper():
                    if self._graph.node(sink_id):
                        edge = AttackEdge(
                            source_id   = vnode.node_id,
                            target_id   = sink_id,
                            kind        = EdgeKind.DATA_FLOW,
                            label       = f"{vnode.label} reaches {sink_id}",
                            weight      = 1.0,
                            probability = 0.9 * vnode.confidence,
                        )
                        self._graph.add_edge(edge)
