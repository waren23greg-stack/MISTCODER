"""
MISTCODER  MOD-03  |  Path Analyzer
─────────────────────────────────────────────────────────────────────────────
Runs shortest-path and all-paths algorithms over the AttackGraph to find:

  • The EASIEST path an attacker can take from any source to any sink
  • ALL viable attack paths, ranked by exploitability
  • Dead-end analysis (nodes that look dangerous but are unreachable from any sink)
  • Blast radius per vulnerability (how many sinks it can contribute to)

Algorithm choices:
  • Dijkstra   – minimum-weight path (most likely exploit chain)
  • DFS + pruning – enumerate all paths with cycle detection
  • Reverse BFS   – compute reachability from sinks backwards
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from attack_graph import AttackGraph, AttackNode, AttackEdge, NodeKind, Severity


# ──────────────────────────────────────────────────────────────────────────────
# Result types
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class AttackPath:
    """A single realised path from source → sink through the graph."""

    nodes:       List[AttackNode]
    edges:       List[AttackEdge]
    total_weight: float
    probability:  float              # joint probability of traversing every edge

    @property
    def length(self) -> int:
        return len(self.nodes)

    @property
    def start(self) -> Optional[AttackNode]:
        return self.nodes[0] if self.nodes else None

    @property
    def end(self) -> Optional[AttackNode]:
        return self.nodes[-1] if self.nodes else None

    @property
    def critical_node_count(self) -> int:
        return sum(1 for n in self.nodes if n.severity == Severity.CRITICAL)

    @property
    def exploitability_score(self) -> float:
        """
        Composite score ∈ [0, 100].
        Higher = more dangerous to the defender.
        Formula: (probability × 100) / (1 + log(total_weight))
        """
        import math
        if self.total_weight <= 0:
            return 100.0
        return min(100.0, (self.probability * 100) / (1 + math.log1p(self.total_weight)))

    def hop_labels(self) -> List[str]:
        return [n.label for n in self.nodes]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "length":              self.length,
            "total_weight":        round(self.total_weight, 4),
            "probability":         round(self.probability, 4),
            "exploitability_score": round(self.exploitability_score, 2),
            "critical_nodes":      self.critical_node_count,
            "hops":                self.hop_labels(),
            "nodes":               [n.to_dict() for n in self.nodes],
            "edges":               [e.to_dict() for e in self.edges],
        }

    def __lt__(self, other: "AttackPath") -> bool:
        return self.exploitability_score > other.exploitability_score   # higher is worse


@dataclass
class PathAnalysisResult:
    """Full output of the PathAnalyzer."""

    shortest_paths:         List[AttackPath]   # one per source-sink pair
    all_paths:              List[AttackPath]   # all viable paths, ranked
    unreachable_nodes:      List[AttackNode]   # detected but unreachable from sinks
    blast_radius:           Dict[str, int]     # node_id → number of reachable sinks
    reachability_scores:    Dict[str, float]   # node_id → forward reachability

    @property
    def most_critical_path(self) -> Optional[AttackPath]:
        return self.all_paths[0] if self.all_paths else None

    @property
    def total_viable_paths(self) -> int:
        return len(self.all_paths)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_viable_paths":   self.total_viable_paths,
            "unreachable_count":    len(self.unreachable_nodes),
            "shortest_paths":       [p.to_dict() for p in self.shortest_paths],
            "top_paths":            [p.to_dict() for p in self.all_paths[:10]],
            "unreachable_nodes":    [n.to_dict() for n in self.unreachable_nodes],
            "blast_radius":         self.blast_radius,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Path Analyzer
# ──────────────────────────────────────────────────────────────────────────────

class PathAnalyzer:
    """
    Performs all graph traversal and path analysis over an AttackGraph.

    Usage:
        analyzer = PathAnalyzer(graph, max_paths=50, max_depth=15)
        result   = analyzer.analyze()
    """

    def __init__(
        self,
        graph:      AttackGraph,
        max_paths:  int  = 100,
        max_depth:  int  = 20,
    ) -> None:
        self._g         = graph
        self._max_paths = max_paths
        self._max_depth = max_depth

    def analyze(self) -> PathAnalysisResult:
        # Phase 1: backward BFS from sinks → mark what's reachable
        sink_reachable = self._backward_reachable()

        # Phase 2: Dijkstra from every source to every sink
        shortest = self._all_shortest_paths()

        # Phase 3: DFS to enumerate all viable paths
        all_paths = self._enumerate_all_paths(sink_reachable)

        # Phase 4: blast radius per node
        blast = self._compute_blast_radius(sink_reachable)

        # Phase 5: identify dead-end nodes (in graph, not reachable to sinks)
        unreachable = [
            n for n in self._g.nodes(kind=NodeKind.VULNERABILITY)
            if n.node_id not in sink_reachable
        ]

        # Annotate graph nodes with computed scores
        self._annotate_nodes(sink_reachable, blast)

        return PathAnalysisResult(
            shortest_paths      = shortest,
            all_paths           = sorted(all_paths),
            unreachable_nodes   = unreachable,
            blast_radius        = blast,
            reachability_scores = {nid: 1.0 if nid in sink_reachable else 0.0
                                   for nid in [n.node_id for n in self._g.nodes()]},
        )

    # ── Phase 1: backward reachability ───────────────────────────────────────

    def _backward_reachable(self) -> Set[str]:
        """BFS from every sink travelling edges in reverse."""
        reachable: Set[str] = set()
        queue: List[str]    = [s.node_id for s in self._g.sinks()]

        while queue:
            nid = queue.pop(0)
            if nid in reachable:
                continue
            reachable.add(nid)
            for pred in self._g.predecessors(nid):
                if pred.node_id not in reachable:
                    queue.append(pred.node_id)
        return reachable

    # ── Phase 2: Dijkstra shortest paths ─────────────────────────────────────

    def _dijkstra(
        self,
        source_id: str,
        sink_id:   str,
    ) -> Optional[AttackPath]:
        """
        Standard Dijkstra over effective_weight edges.
        Returns the minimum-weight path or None if unreachable.
        """
        dist:  Dict[str, float]             = {source_id: 0.0}
        prev:  Dict[str, Optional[str]]     = {source_id: None}
        prev_edge: Dict[str, Optional[AttackEdge]] = {source_id: None}
        heap:  List[Tuple[float, str]]      = [(0.0, source_id)]
        visited: Set[str]                   = set()

        while heap:
            cost, uid = heapq.heappop(heap)
            if uid in visited:
                continue
            visited.add(uid)
            if uid == sink_id:
                break
            for edge in self._g.edges_from(uid):
                vid   = edge.target_id
                ncost = cost + edge.effective_weight()
                if ncost < dist.get(vid, float("inf")):
                    dist[vid]      = ncost
                    prev[vid]      = uid
                    prev_edge[vid] = edge
                    heapq.heappush(heap, (ncost, vid))

        if sink_id not in dist:
            return None

        # Reconstruct path
        nodes: List[AttackNode] = []
        edges: List[AttackEdge] = []
        cur = sink_id
        while cur is not None:
            n = self._g.node(cur)
            if n:
                nodes.append(n)
            e = prev_edge.get(cur)
            if e:
                edges.append(e)
            cur = prev.get(cur)

        nodes.reverse()
        edges.reverse()

        # Compute joint probability
        prob = 1.0
        for e in edges:
            prob *= e.probability

        return AttackPath(
            nodes        = nodes,
            edges        = edges,
            total_weight = dist[sink_id],
            probability  = prob,
        )

    def _all_shortest_paths(self) -> List[AttackPath]:
        results: List[AttackPath] = []
        for src in self._g.sources():
            for snk in self._g.sinks():
                path = self._dijkstra(src.node_id, snk.node_id)
                if path:
                    results.append(path)
        return results

    # ── Phase 3: enumerate all viable paths ──────────────────────────────────

    def _enumerate_all_paths(self, sink_reachable: Set[str]) -> List[AttackPath]:
        """DFS with pruning: only visit nodes that can reach a sink."""
        collected: List[AttackPath] = []
        sink_ids = {s.node_id for s in self._g.sinks()}

        def dfs(
            nid:       str,
            visited:   Set[str],
            cur_nodes: List[AttackNode],
            cur_edges: List[AttackEdge],
            weight:    float,
            prob:      float,
        ) -> None:
            if len(collected) >= self._max_paths:
                return
            if len(cur_nodes) > self._max_depth:
                return

            node = self._g.node(nid)
            if not node:
                return

            cur_nodes.append(node)

            if nid in sink_ids and len(cur_nodes) > 1:
                collected.append(AttackPath(
                    nodes        = list(cur_nodes),
                    edges        = list(cur_edges),
                    total_weight = weight,
                    probability  = prob,
                ))

            for edge in self._g.edges_from(nid):
                tid = edge.target_id
                if tid in visited:
                    continue          # cycle guard
                if tid not in sink_reachable:
                    continue          # prune dead ends
                visited.add(tid)
                cur_edges.append(edge)
                dfs(
                    tid, visited, cur_nodes, cur_edges,
                    weight + edge.effective_weight(),
                    prob * edge.probability,
                )
                cur_edges.pop()
                visited.discard(tid)

            cur_nodes.pop()

        for src in self._g.sources():
            sid = src.node_id
            if sid not in sink_reachable:
                continue
            dfs(sid, {sid}, [], [], 0.0, 1.0)

        return collected

    # ── Phase 4: blast radius ─────────────────────────────────────────────────

    def _compute_blast_radius(self, sink_reachable: Set[str]) -> Dict[str, int]:
        """
        For each node, count how many distinct sinks it can reach.
        Uses forward BFS constrained to sink_reachable nodes.
        """
        blast: Dict[str, int] = {}
        sink_ids = {s.node_id for s in self._g.sinks()}

        for vnode in self._g.nodes(kind=NodeKind.VULNERABILITY):
            if vnode.node_id not in sink_reachable:
                blast[vnode.node_id] = 0
                continue

            reachable_sinks: Set[str] = set()
            queue   = [vnode.node_id]
            visited: Set[str] = set()

            while queue:
                cur = queue.pop(0)
                if cur in visited:
                    continue
                visited.add(cur)
                if cur in sink_ids:
                    reachable_sinks.add(cur)
                for edge in self._g.edges_from(cur):
                    if edge.target_id not in visited and edge.target_id in sink_reachable:
                        queue.append(edge.target_id)

            blast[vnode.node_id] = len(reachable_sinks)

        return blast

    # ── Phase 5: node annotation ─────────────────────────────────────────────

    def _annotate_nodes(
        self,
        sink_reachable: Set[str],
        blast: Dict[str, int],
    ) -> None:
        total_sinks = max(1, len(list(self._g.sinks())))
        for node in self._g.nodes():
            node.reachability_score = (
                1.0 if node.node_id in sink_reachable else 0.0
            )
            br = blast.get(node.node_id, 0)
            node.impact_score = br / total_sinks
