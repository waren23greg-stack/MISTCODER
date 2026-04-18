"""
MISTCODER -- MOD-07 Knowledge Graph Integration v0.1.0

Builds a persistent, queryable property graph of the entire
attack surface across multiple scans and codebases.

Architecture
------------
Nodes represent entities:
    Software      -- scanned files, repos, services
    Vulnerability -- findings with full CVSS context
    Attacker      -- modelled threat actors
    Asset         -- data stores, auth boundaries, endpoints
    CVE           -- known vulnerability records
    Pattern       -- learned attack patterns from LEARN module

Edges represent relationships:
    CONTAINS      -- software contains vulnerability
    EXPLOITS      -- attacker exploits vulnerability
    AFFECTS       -- CVE affects software
    CHAINS_TO     -- vulnerability chains to another
    SIMILAR_TO    -- pattern similarity (cosine weight)
    MITIGATED_BY  -- vulnerability mitigated by control
    TARGETS       -- attacker targets asset

Storage
-------
In-memory graph with JSON persistence.
Designed to be swapped for Neo4j in Phase 3 production.
Interface is identical -- only the backend changes.

Output
------
GraphReport: ranked attack surface, cross-scan chains,
threat actor profiles, asset exposure scores.
"""

import json
import os
import uuid
import math
from datetime import datetime, timezone
from collections import defaultdict, deque
from typing import Optional


# ---------------------------------------------------------------------------
# Node and Edge types
# ---------------------------------------------------------------------------

NODE_TYPES = {
    "SOFTWARE",
    "VULNERABILITY",
    "ATTACKER",
    "ASSET",
    "CVE",
    "PATTERN",
    "CONTROL",
    "SERVICE",
}

EDGE_TYPES = {
    "CONTAINS",
    "EXPLOITS",
    "AFFECTS",
    "CHAINS_TO",
    "SIMILAR_TO",
    "MITIGATED_BY",
    "TARGETS",
    "RELATES_TO",
    "DISCOVERED_IN",
}

SEVERITY_WEIGHT = {
    "CRITICAL": 1.0,
    "HIGH":     0.75,
    "MEDIUM":   0.50,
    "LOW":      0.25,
    "INFO":     0.10,
    "NONE":     0.0,
}


# ---------------------------------------------------------------------------
# Graph node and edge
# ---------------------------------------------------------------------------

class KGNode:
    """A node in the knowledge graph."""

    def __init__(self, node_id: str, node_type: str,
                 name: str, properties: Optional[dict] = None):
        if node_type not in NODE_TYPES:
            raise ValueError(f"Invalid node type: {node_type}")
        self.id         = node_id
        self.type       = node_type
        self.name       = name
        self.properties = properties or {}
        self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "type":       self.type,
            "name":       self.name,
            "properties": self.properties,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KGNode":
        node = cls(d["id"], d["type"], d["name"], d.get("properties", {}))
        node.created_at = d.get("created_at", node.created_at)
        return node


class KGEdge:
    """A directed edge in the knowledge graph."""

    def __init__(self, edge_id: str, src_id: str, dst_id: str,
                 edge_type: str, weight: float = 1.0,
                 properties: Optional[dict] = None):
        if edge_type not in EDGE_TYPES:
            raise ValueError(f"Invalid edge type: {edge_type}")
        self.id         = edge_id
        self.src        = src_id
        self.dst        = dst_id
        self.type       = edge_type
        self.weight     = weight
        self.properties = properties or {}
        self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "src":        self.src,
            "dst":        self.dst,
            "type":       self.type,
            "weight":     self.weight,
            "properties": self.properties,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KGEdge":
        edge = cls(d["id"], d["src"], d["dst"], d["type"],
                   d.get("weight", 1.0), d.get("properties", {}))
        edge.created_at = d.get("created_at", edge.created_at)
        return edge


# ---------------------------------------------------------------------------
# In-memory graph store
# ---------------------------------------------------------------------------

class GraphStore:
    """
    In-memory property graph with JSON persistence.
    Drop-in replacement interface for Neo4j backend.
    """

    def __init__(self):
        self._nodes: dict[str, KGNode] = {}
        self._edges: dict[str, KGEdge] = {}
        self._forward: dict  = defaultdict(list)
        self._backward: dict = defaultdict(list)
        self._type_index: dict = defaultdict(set)
        self._name_index: dict = defaultdict(set)

    # -- Node operations

    def add_node(self, node: KGNode) -> KGNode:
        self._nodes[node.id] = node
        self._type_index[node.type].add(node.id)
        self._name_index[node.name.lower()].add(node.id)
        return node

    def get_node(self, node_id: str) -> Optional[KGNode]:
        return self._nodes.get(node_id)

    def find_nodes_by_type(self, node_type: str) -> list:
        return [self._nodes[nid] for nid in self._type_index.get(node_type, set())
                if nid in self._nodes]

    def find_nodes_by_name(self, name: str) -> list:
        return [self._nodes[nid]
                for nid in self._name_index.get(name.lower(), set())
                if nid in self._nodes]

    def find_nodes_by_property(self, key: str, value) -> list:
        return [n for n in self._nodes.values()
                if n.properties.get(key) == value]

    def upsert_node(self, node_type: str, name: str,
                    properties: Optional[dict] = None) -> KGNode:
        existing = self.find_nodes_by_name(name)
        for n in existing:
            if n.type == node_type:
                if properties:
                    n.properties.update(properties)
                return n
        node = KGNode(str(uuid.uuid4()), node_type, name, properties)
        return self.add_node(node)

    def remove_node(self, node_id: str) -> bool:
        if node_id not in self._nodes:
            return False
        node = self._nodes.pop(node_id)
        self._type_index[node.type].discard(node_id)
        self._name_index[node.name.lower()].discard(node_id)
        edges_to_remove = [
            eid for eid, e in self._edges.items()
            if e.src == node_id or e.dst == node_id
        ]
        for eid in edges_to_remove:
            self.remove_edge(eid)
        return True

    # -- Edge operations

    def add_edge(self, edge: KGEdge) -> KGEdge:
        self._edges[edge.id] = edge
        self._forward[edge.src].append(edge.id)
        self._backward[edge.dst].append(edge.id)
        return edge

    def get_edge(self, edge_id: str) -> Optional[KGEdge]:
        return self._edges.get(edge_id)

    def remove_edge(self, edge_id: str) -> bool:
        if edge_id not in self._edges:
            return False
        edge = self._edges.pop(edge_id)
        self._forward[edge.src] = [
            e for e in self._forward[edge.src] if e != edge_id
        ]
        self._backward[edge.dst] = [
            e for e in self._backward[edge.dst] if e != edge_id
        ]
        return True

    def connect(self, src_id: str, dst_id: str,
                edge_type: str, weight: float = 1.0,
                properties: Optional[dict] = None) -> Optional[KGEdge]:
        if src_id not in self._nodes or dst_id not in self._nodes:
            return None
        existing = self.get_edge_between(src_id, dst_id, edge_type)
        if existing:
            existing.weight = max(existing.weight, weight)
            return existing
        edge = KGEdge(str(uuid.uuid4()), src_id, dst_id,
                      edge_type, weight, properties)
        return self.add_edge(edge)

    def get_edge_between(self, src_id: str, dst_id: str,
                         edge_type: str) -> Optional[KGEdge]:
        for eid in self._forward.get(src_id, []):
            e = self._edges.get(eid)
            if e and e.dst == dst_id and e.type == edge_type:
                return e
        return None

    def successors(self, node_id: str,
                   edge_type: Optional[str] = None) -> list:
        result = []
        for eid in self._forward.get(node_id, []):
            e = self._edges.get(eid)
            if e and (edge_type is None or e.type == edge_type):
                n = self._nodes.get(e.dst)
                if n:
                    result.append(n)
        return result

    def predecessors(self, node_id: str,
                     edge_type: Optional[str] = None) -> list:
        result = []
        for eid in self._backward.get(node_id, []):
            e = self._edges.get(eid)
            if e and (edge_type is None or e.type == edge_type):
                n = self._nodes.get(e.src)
                if n:
                    result.append(n)
        return result

    # -- Graph traversal

    def bfs(self, start_id: str, edge_type: Optional[str] = None,
            max_depth: int = 6) -> list:
        visited = []
        queue   = deque([(start_id, 0)])
        seen    = {start_id}
        while queue:
            nid, depth = queue.popleft()
            node = self._nodes.get(nid)
            if node:
                visited.append(node)
            if depth >= max_depth:
                continue
            for succ in self.successors(nid, edge_type):
                if succ.id not in seen:
                    seen.add(succ.id)
                    queue.append((succ.id, depth + 1))
        return visited

    def shortest_path(self, src_id: str,
                      dst_id: str) -> Optional[list]:
        if src_id == dst_id:
            return [src_id]
        queue   = deque([[src_id]])
        visited = {src_id}
        while queue:
            path = queue.popleft()
            for succ in self.successors(path[-1]):
                if succ.id == dst_id:
                    return path + [succ.id]
                if succ.id not in visited:
                    visited.add(succ.id)
                    queue.append(path + [succ.id])
        return None

    def all_paths(self, src_id: str, dst_id: str,
                  max_depth: int = 8) -> list:
        results = []
        stack   = [(src_id, [src_id])]
        while stack:
            nid, path = stack.pop()
            if nid == dst_id:
                results.append(path)
                continue
            if len(path) >= max_depth:
                continue
            for succ in self.successors(nid):
                if succ.id not in path:
                    stack.append((succ.id, path + [succ.id]))
        return results

    # -- Statistics

    def stats(self) -> dict:
        type_counts = {t: len(ids)
                       for t, ids in self._type_index.items() if ids}
        edge_counts = defaultdict(int)
        for e in self._edges.values():
            edge_counts[e.type] += 1
        return {
            "node_count":  len(self._nodes),
            "edge_count":  len(self._edges),
            "node_types":  type_counts,
            "edge_types":  dict(edge_counts),
        }

    # -- Persistence

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        data = {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges.values()],
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for nd in data.get("nodes", []):
            self.add_node(KGNode.from_dict(nd))
        for ed in data.get("edges", []):
            self.add_edge(KGEdge.from_dict(ed))

    def clear(self) -> None:
        self._nodes.clear()
        self._edges.clear()
        self._forward.clear()
        self._backward.clear()
        self._type_index.clear()
        self._name_index.clear()


# ---------------------------------------------------------------------------
# Attack surface scorer
# ---------------------------------------------------------------------------

class AttackSurfaceScorer:
    """
    Scores each node by its exposure on the attack surface.
    Uses PageRank-inspired propagation -- nodes connected to
    high-severity vulnerabilities inherit elevated scores.
    """

    DAMPING     = 0.85
    ITERATIONS  = 20

    def __init__(self, store: GraphStore):
        self.store = store

    def score(self) -> dict:
        nodes = list(self.store._nodes.values())
        if not nodes:
            return {}

        scores = {}
        for node in nodes:
            base = SEVERITY_WEIGHT.get(
                node.properties.get("severity", "NONE"), 0.1
            )
            if node.type == "VULNERABILITY":
                base = max(base, 0.5)
            elif node.type == "CVE":
                base = max(base, 0.4)
            elif node.type == "ASSET":
                base = max(base, 0.3)
            scores[node.id] = base

        n = len(nodes)
        for _ in range(self.ITERATIONS):
            new_scores = {}
            for node in nodes:
                incoming = self.store.predecessors(node.id)
                if not incoming:
                    new_scores[node.id] = (1 - self.DAMPING) / n
                else:
                    rank_sum = sum(
                        scores.get(pred.id, 0.0) /
                        max(len(self.store.successors(pred.id)), 1)
                        for pred in incoming
                    )
                    new_scores[node.id] = (
                        (1 - self.DAMPING) / n +
                        self.DAMPING * rank_sum
                    )
            scores = new_scores

        return scores


# ---------------------------------------------------------------------------
# Graph builder -- ingests MISTCODER pipeline output
# ---------------------------------------------------------------------------

class KnowledgeGraphBuilder:
    """
    Builds the knowledge graph from MISTCODER pipeline outputs.
    Accepts IR, analysis report, reasoning result, CVSS scores.
    Handles multiple scans -- merges by name deduplication.
    """

    def __init__(self, store: GraphStore):
        self.store = store

    def ingest_scan(self, ir: dict, analysis_report: dict,
                    reasoning_result: Optional[dict] = None,
                    cvss_result: Optional[dict] = None,
                    target_label: Optional[str] = None) -> dict:
        target = target_label or ir.get("file", "unknown")
        stats  = {"nodes_added": 0, "edges_added": 0}

        # Software node
        sw_node = self.store.upsert_node("SOFTWARE", target, {
            "language":   ir.get("language", "unknown"),
            "scan_type":  ir.get("scan_type", "file"),
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        })
        stats["nodes_added"] += 1

        # Finding nodes
        findings     = analysis_report.get("findings", [])
        finding_map  = {}

        for finding in findings:
            fid      = finding.get("id", str(uuid.uuid4()))
            category = finding.get("category", "UNKNOWN")
            severity = finding.get("severity", "LOW").upper()

            cvss_score = 0.0
            if cvss_result:
                for sf in cvss_result.get("scores", []):
                    if sf.get("finding_id") == fid:
                        cvss_score = sf.get("context_score", 0.0)
                        break

            vuln_node = self.store.upsert_node("VULNERABILITY",
                f"{target}::{category}::{finding.get('line', 0)}", {
                    "finding_id":  fid,
                    "category":    category,
                    "severity":    severity,
                    "description": finding.get("description", ""),
                    "line":        finding.get("line"),
                    "cvss_score":  cvss_score,
                })
            finding_map[fid] = vuln_node
            stats["nodes_added"] += 1

            edge = self.store.connect(
                sw_node.id, vuln_node.id, "CONTAINS",
                weight=SEVERITY_WEIGHT.get(severity, 0.1)
            )
            if edge:
                stats["edges_added"] += 1

        # Chain edges
        if reasoning_result:
            for chain in reasoning_result.get("chains", []):
                links    = chain.get("links", [])
                sev      = chain.get("combined_severity", "medium").upper()
                weight   = SEVERITY_WEIGHT.get(sev, 0.5)
                for i in range(len(links) - 1):
                    src_node = finding_map.get(links[i])
                    dst_node = finding_map.get(links[i + 1])
                    if src_node and dst_node:
                        edge = self.store.connect(
                            src_node.id, dst_node.id,
                            "CHAINS_TO", weight=weight,
                            properties={"chain_id": chain.get("id")}
                        )
                        if edge:
                            stats["edges_added"] += 1

            # Anomaly nodes
            for anomaly in reasoning_result.get("anomalies", []):
                anode = self.store.upsert_node("VULNERABILITY",
                    f"{target}::ANOMALY::{anomaly.get('function_name', '')}",
                    {
                        "category":    "BEHAVIORAL_ANOMALY",
                        "severity":    anomaly.get("severity", "MEDIUM").upper(),
                        "description": anomaly.get("violation", ""),
                        "function":    anomaly.get("function_name", ""),
                    })
                stats["nodes_added"] += 1
                edge = self.store.connect(
                    sw_node.id, anode.id, "CONTAINS", weight=0.4
                )
                if edge:
                    stats["edges_added"] += 1

        return {
            "target":       target,
            "software_id":  sw_node.id,
            "stats":        stats,
            "graph_stats":  self.store.stats(),
        }

    def add_cve(self, cve_id: str, description: str,
                severity: str, cvss_score: float,
                affected_software: Optional[list] = None) -> KGNode:
        cve_node = self.store.upsert_node("CVE", cve_id, {
            "description": description,
            "severity":    severity.upper(),
            "cvss_score":  cvss_score,
        })
        if affected_software:
            for sw_name in affected_software:
                sw_nodes = self.store.find_nodes_by_name(sw_name)
                for sw in sw_nodes:
                    if sw.type == "SOFTWARE":
                        self.store.connect(
                            cve_node.id, sw.id, "AFFECTS",
                            weight=SEVERITY_WEIGHT.get(severity.upper(), 0.5)
                        )
        return cve_node

    def add_threat_actor(self, name: str,
                         capabilities: Optional[list] = None,
                         targets: Optional[list] = None) -> KGNode:
        actor = self.store.upsert_node("ATTACKER", name, {
            "capabilities": capabilities or [],
            "target_count": len(targets or []),
        })
        if targets:
            for target_name in targets:
                target_nodes = self.store.find_nodes_by_name(target_name)
                for tn in target_nodes:
                    self.store.connect(
                        actor.id, tn.id, "TARGETS", weight=0.8
                    )
        return actor


# ---------------------------------------------------------------------------
# Graph query engine
# ---------------------------------------------------------------------------

class GraphQueryEngine:
    """
    High-level query interface over the knowledge graph.
    Returns ranked, structured results.
    """

    def __init__(self, store: GraphStore):
        self.store   = store
        self._scorer = AttackSurfaceScorer(store)

    def top_vulnerabilities(self, limit: int = 10) -> list:
        vulns  = self.store.find_nodes_by_type("VULNERABILITY")
        scores = self._scorer.score()
        ranked = sorted(vulns,
                        key=lambda n: scores.get(n.id, 0.0),
                        reverse=True)
        return [
            {
                "id":          n.id,
                "name":        n.name,
                "severity":    n.properties.get("severity", "UNKNOWN"),
                "category":    n.properties.get("category", "UNKNOWN"),
                "cvss_score":  n.properties.get("cvss_score", 0.0),
                "graph_score": round(scores.get(n.id, 0.0), 4),
                "chains":      len(self.store.successors(n.id, "CHAINS_TO")),
            }
            for n in ranked[:limit]
        ]

    def cross_scan_chains(self) -> list:
        chains = []
        vulns  = self.store.find_nodes_by_type("VULNERABILITY")
        for vuln in vulns:
            chain_targets = self.store.successors(vuln.id, "CHAINS_TO")
            if not chain_targets:
                continue
            sw_src = self.store.predecessors(vuln.id, "CONTAINS")
            for target in chain_targets:
                sw_dst = self.store.predecessors(target.id, "CONTAINS")
                src_names = [s.name for s in sw_src]
                dst_names = [d.name for d in sw_dst]
                if set(src_names) != set(dst_names):
                    chains.append({
                        "source_vuln":    vuln.name,
                        "target_vuln":    target.name,
                        "source_software": src_names,
                        "target_software": dst_names,
                        "cross_scan":     True,
                    })
        return chains

    def asset_exposure(self) -> list:
        scores = self._scorer.score()
        assets = self.store.find_nodes_by_type("ASSET")
        return sorted(
            [
                {
                    "id":            a.id,
                    "name":          a.name,
                    "exposure_score": round(scores.get(a.id, 0.0), 4),
                    "vuln_count":    len(self.store.predecessors(
                                         a.id, "TARGETS")),
                }
                for a in assets
            ],
            key=lambda x: x["exposure_score"],
            reverse=True
        )

    def threat_actor_reach(self) -> list:
        actors = self.store.find_nodes_by_type("ATTACKER")
        result = []
        for actor in actors:
            reachable = self.store.bfs(actor.id, max_depth=4)
            vulns     = [n for n in reachable
                         if n.type == "VULNERABILITY"]
            result.append({
                "actor":        actor.name,
                "capabilities": actor.properties.get("capabilities", []),
                "reachable_vulns": len(vulns),
                "reach_nodes":  len(reachable),
            })
        return sorted(result,
                      key=lambda x: x["reachable_vulns"],
                      reverse=True)

    def vulnerability_clusters(self,
                               min_cluster_size: int = 2) -> list:
        vulns  = self.store.find_nodes_by_type("VULNERABILITY")
        visited: set = set()
        clusters     = []

        for vuln in vulns:
            if vuln.id in visited:
                continue
            cluster = self.store.bfs(
                vuln.id, edge_type="CHAINS_TO", max_depth=5
            )
            if len(cluster) >= min_cluster_size:
                for n in cluster:
                    visited.add(n.id)
                clusters.append({
                    "size":     len(cluster),
                    "members":  [n.name for n in cluster],
                    "severity": max(
                        (SEVERITY_WEIGHT.get(
                            n.properties.get("severity", "NONE"), 0)
                         for n in cluster),
                        default=0.0
                    ),
                })

        return sorted(clusters,
                      key=lambda x: x["severity"],
                      reverse=True)


# ---------------------------------------------------------------------------
# Knowledge Graph Engine -- main entry point
# ---------------------------------------------------------------------------

class KnowledgeGraphEngine:
    """
    MOD-07 entry point.
    Manages the persistent knowledge graph across scan sessions.
    """

    def __init__(self, storage_path: Optional[str] = None):
        self.store   = GraphStore()
        self.builder = KnowledgeGraphBuilder(self.store)
        self.query   = GraphQueryEngine(self.store)
        self._path   = storage_path

        if storage_path and os.path.isfile(storage_path):
            self.store.load(storage_path)
            print(f"[MOD-07] Loaded graph from {storage_path} "
                  f"-- {self.store.stats()['node_count']} nodes")

    def ingest(self, ir: dict, analysis_report: dict,
               reasoning_result: Optional[dict] = None,
               cvss_result: Optional[dict] = None,
               target_label: Optional[str] = None) -> dict:
        result = self.builder.ingest_scan(
            ir, analysis_report, reasoning_result,
            cvss_result, target_label
        )
        if self._path:
            self.store.save(self._path)
        return result

    def report(self) -> dict:
        stats      = self.store.stats()
        top_vulns  = self.query.top_vulnerabilities(10)
        clusters   = self.query.vulnerability_clusters()
        chains     = self.query.cross_scan_chains()
        actors     = self.query.threat_actor_reach()

        risk = "NONE"
        if top_vulns:
            top_sev = top_vulns[0].get("severity", "NONE")
            risk    = top_sev

        return {
            "graph_stats":       stats,
            "top_vulnerabilities": top_vulns,
            "vulnerability_clusters": clusters,
            "cross_scan_chains": chains,
            "threat_actor_reach": actors,
            "overall_risk":      risk,
            "metadata": {
                "engine":       "KnowledgeGraphEngine v0.1.0",
                "reported_at":  datetime.now(timezone.utc).isoformat(),
            }
        }

    def save(self, path: Optional[str] = None) -> None:
        target = path or self._path
        if target:
            self.store.save(target)
            print(f"[MOD-07] Graph saved to {target}")

    def stats(self) -> dict:
        return self.store.stats()
