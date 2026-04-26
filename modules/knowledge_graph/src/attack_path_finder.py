"""
MISTCODER MOD-07 — Attack Path Finder
Version 0.1.0 — Discovery and scoring of adversarial paths
"""

from typing import List, Dict, Optional, Tuple, Any
from collections import deque
from datetime import datetime, timezone
import json


class AttackPath:
    """Represents a single attack path through the threat graph"""

    def __init__(self, path_id: str, nodes: List[Dict], edges: List[Dict]):
        self.path_id = path_id
        self.nodes = nodes  # List of node IDs
        self.edges = edges  # List of edge relationships
        self.length = len(nodes)
        self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict:
        return {
            "path_id": self.path_id,
            "nodes": self.nodes,
            "edges": self.edges,
            "length": self.length,
            "created_at": self.created_at
        }


class PathScorer:
    """
    Scores attack paths on multiple dimensions:
    - Exploitability: How easy is each step?
    - Impact: What's the value of the target?
    - Probability: What's the likelihood of success?
    - Detectability: How likely to be caught?
    """

    # Severity -> exploitability score mapping
    SEVERITY_TO_EXPLOITABILITY = {
        "CRITICAL": 1.0,
        "HIGH": 0.85,
        "MEDIUM": 0.65,
        "LOW": 0.40,
        "INFO": 0.10
    }

    # Asset sensitivity -> impact score
    SENSITIVITY_TO_IMPACT = {
        "CRITICAL": 1.0,
        "HIGH": 0.75,
        "MEDIUM": 0.50,
        "LOW": 0.25
    }

    @staticmethod
    def score_path(nodes: List[Dict], edges: List[Dict]) -> Dict[str, Any]:
        """
        Score a path based on:
        1. Average exploitability of vulnerabilities
        2. Impact of target asset
        3. Path length (longer = harder)
        4. Confidence scores on edges
        """
        
        if not nodes or not edges:
            return {
                "exploitability": 0.0,
                "impact": 0.0,
                "probability": 0.0,
                "detectability": 0.0,
                "overall_score": 0.0
            }

        # Exploitability: average CVSS of weaknesses in path
        vuln_nodes = [n for n in nodes if n.get("type") == "Weakness"]
        if vuln_nodes:
            cvss_scores = [n.get("cvss_score", 5.0) / 10.0 for n in vuln_nodes]
            exploitability = sum(cvss_scores) / len(cvss_scores)
        else:
            exploitability = 0.5  # Default if no vulns explicitly scored

        # Impact: sensitivity of target asset
        asset_nodes = [n for n in nodes if n.get("type") == "Asset"]
        if asset_nodes:
            target = asset_nodes[-1]  # Last asset in path
            sensitivity = target.get("sensitivity", "MEDIUM")
            impact = PathScorer.SENSITIVITY_TO_IMPACT.get(sensitivity, 0.5)
        else:
            impact = 0.5

        # Probability: product of edge confidences
        edge_confidences = [e.get("confidence", 0.8) for e in edges]
        probability = 1.0
        for conf in edge_confidences:
            probability *= conf
        
        # Detectability: inverse of average detection_probability on edges
        detection_probs = [e.get("detection_probability", 0.3) for e in edges]
        avg_detection = sum(detection_probs) / len(detection_probs) if detection_probs else 0.3
        detectability = 1.0 - avg_detection  # Higher detectability = lower detection prob

        # Length penalty: longer paths are harder to execute
        length_penalty = 1.0 / (1.0 + (len(nodes) - 1) * 0.1)

        # Overall score: weighted combination
        overall = (
            0.3 * exploitability +
            0.3 * impact +
            0.2 * probability +
            0.1 * detectability +
            0.1 * length_penalty
        ) * 10.0  # Scale to 0-10

        return {
            "exploitability": round(exploitability, 3),
            "impact": round(impact, 3),
            "probability": round(probability, 3),
            "detectability": round(detectability, 3),
            "length_penalty": round(length_penalty, 3),
            "overall_score": round(min(overall, 10.0), 2)
        }


class AttackPathFinder:
    """
    Discovers attack paths in a knowledge graph.
    Uses BFS/DFS to find all paths from attacker positions to assets.
    """

    def __init__(self, graph_backend):
        """
        graph_backend: GraphBackend instance (Neo4j or In-Memory)
        """
        self.graph = graph_backend
        self._path_counter = 0

    def _next_path_id(self) -> str:
        """Generate unique path ID"""
        self._path_counter += 1
        return f"PATH-{self._path_counter:04d}"

    def find_all_paths(
        self,
        start_id: str,
        end_id: str,
        max_length: int = 5
    ) -> List[AttackPath]:
        """
        Find all attack paths from start node to end node.
        Uses DFS to enumerate all simple paths (no cycles).
        """
        paths = []
        visited = set()
        stack = [(start_id, [start_id], [])]

        while stack:
            current, node_path, edge_path = stack.pop()

            # Found the target
            if current == end_id:
                path = AttackPath(
                    path_id=self._next_path_id(),
                    nodes=node_path,
                    edges=edge_path
                )
                paths.append(path)
                continue

            # Reached max depth
            if len(node_path) >= max_length:
                continue

            # Explore neighbors (successors)
            # Note: In real implementation, would query graph backend
            # For now, this is a placeholder for the search logic
            current_node = self.graph.find_node(current)
            if not current_node:
                continue

            # Get reachable nodes
            reachable = self.graph.reachable_from(current)
            for next_node in reachable:
                next_id = next_node.get("id")
                if next_id not in node_path and next_id not in visited:
                    # In real implementation, would get edge properties
                    edge_info = {
                        "src": current,
                        "dst": next_id,
                        "type": "traversal",
                        "confidence": 0.8
                    }
                    stack.append(
                        (next_id, node_path + [next_id], edge_path + [edge_info])
                    )

        return paths

    def find_critical_paths(
        self,
        attacker_position: str,
        asset_type: str = "Asset",
        min_score: float = 7.0
    ) -> List[Tuple[AttackPath, Dict]]:
        """
        Find attack paths that score above threshold.
        Returns (path, scoring_details) tuples.
        """
        critical_paths = []

        # Find all assets of target type
        target_assets = self.graph.find_nodes_by_type(asset_type)
        
        # For each asset, find paths from attacker
        for asset in target_assets:
            asset_id = asset.get("id")
            paths = self.find_all_paths(attacker_position, asset_id, max_length=5)
            
            for path in paths:
                # Reconstruct node and edge data for scoring
                nodes_data = []
                for node_id in path.nodes:
                    node = self.graph.find_node(node_id)
                    if node:
                        nodes_data.append(node)
                
                scoring = PathScorer.score_path(nodes_data, path.edges)
                
                if scoring["overall_score"] >= min_score:
                    critical_paths.append((path, scoring))

        # Sort by score (descending)
        critical_paths.sort(
            key=lambda x: x[1]["overall_score"],
            reverse=True
        )

        return critical_paths
    def find_shortest_path(self, start_id: str, end_id: str) -> Optional[AttackPath]:
        """
        Find the shortest attack path using BFS.
        Useful for efficiency analysis.
        """
        # Check if nodes exist
        start_node = self.graph.find_node(start_id)
        end_node = self.graph.find_node(end_id)
        
        if not start_node or not end_node:
            return None
        
        queue = deque([(start_id, [start_id], [])])
        visited = {start_id}

        while queue:
            current, node_path, edge_path = queue.popleft()

            if current == end_id:
                return AttackPath(
                    path_id=self._next_path_id(),
                    nodes=node_path,
                    edges=edge_path
                )

            # Get all edges from current node (manually check backend)
            # For in-memory backend, iterate through edges
            if hasattr(self.graph, 'edges'):
                # In-memory backend
                for (src, dst), edge in self.graph.edges.items():
                    if src == current and dst not in visited:
                        visited.add(dst)
                        edge_info = {
                            "src": current,
                            "dst": dst,
                            "type": edge.get("type", "traversal"),
                            "confidence": edge.get("properties", {}).get("confidence", 0.8)
                        }
                        queue.append(
                            (dst, node_path + [dst], edge_path + [edge_info])
                        )
            else:
                # Neo4j backend - use reachability
                reachable = self.graph.reachable_from(current)
                for next_node in reachable:
                    next_id = next_node.get("id")
                    if next_id not in visited:
                        visited.add(next_id)
                        edge_info = {
                            "src": current,
                            "dst": next_id,
                            "type": "traversal",
                            "confidence": 0.8
                        }
                        queue.append(
                            (next_id, node_path + [next_id], edge_path + [edge_info])
                        )

        return None
    def find_diversified_paths(
        self,
        attacker_position: str,
        target_asset: str,
        num_paths: int = 5,
        diversity_threshold: float = 0.5
    ) -> List[AttackPath]:
        """
        Find attack paths that are diverse (use different vulnerabilities).
        Avoids returning nearly-identical paths.
        """
        all_paths = self.find_all_paths(attacker_position, target_asset)
        
        if not all_paths:
            return []

        diverse_paths = [all_paths[0]]

        for path in all_paths[1:]:
            if len(diverse_paths) >= num_paths:
                break

            # Check diversity: what fraction of nodes are different?
            common_nodes = len(set(path.nodes) & set(diverse_paths[-1].nodes))
            diversity = 1.0 - (common_nodes / len(path.nodes))

            if diversity >= diversity_threshold:
                diverse_paths.append(path)

        return diverse_paths

    def find_alternative_paths(
        self,
        primary_path: AttackPath,
        attacker_position: str,
        target_asset: str
    ) -> List[AttackPath]:
        """
        Find alternative paths that avoid certain nodes in primary path.
        Useful for understanding defenses.
        """
        blocked_nodes = set(primary_path.nodes)

        # This is a simplified version; real implementation would
        # need to query with node exclusions
        alternatives = []
        all_paths = self.find_all_paths(attacker_position, target_asset)

        for path in all_paths:
            # Path is alternative if it shares < 50% of nodes with primary
            overlap = len(set(path.nodes) & blocked_nodes) / len(path.nodes)
            if overlap < 0.5:
                alternatives.append(path)

        return alternatives


class AdversaryModeler:
    """
    Models different adversary tiers and their capabilities.
    Filters attack paths by what tier of adversary can execute them.
    """

    TIERS = {
        "T1": {"name": "Opportunistic", "require_public_exploit": True, "custom_tooling": False},
        "T2": {"name": "Skilled", "require_public_exploit": False, "custom_tooling": True},
        "T3": {"name": "Advanced", "require_public_exploit": False, "custom_tooling": True},
        "T4": {"name": "Nation-State", "require_public_exploit": False, "custom_tooling": True},
    }

    @staticmethod
    def filter_by_tier(paths: List[Tuple[AttackPath, Dict]], tier: str) -> List[Tuple[AttackPath, Dict]]:
        """
        Filter paths to only those executable by a given adversary tier.
        """
        tier_info = AdversaryModeler.TIERS.get(tier, {})
        require_public = tier_info.get("require_public_exploit", True)

        filtered = []
        for path, scoring in paths:
            # T1 requires high exploitability (public exploit available)
            if tier == "T1" and scoring["exploitability"] < 0.8:
                continue

            # T2-T4 can work with lower exploitability
            if tier in ["T2", "T3", "T4"]:
                if scoring["exploitability"] < 0.3:
                    continue

            # T4 can execute paths up to 10 steps long
            # T1 limited to 2-3 step chains
            if tier == "T1" and path.length > 3:
                continue
            elif tier == "T2" and path.length > 6:
                continue

            filtered.append((path, scoring))

        return filtered

    @staticmethod
    def get_exploitable_by_tiers(
        paths: List[Tuple[AttackPath, Dict]]
    ) -> Dict[str, List[Tuple[AttackPath, Dict]]]:
        """
        For each path, determine which adversary tiers can execute it.
        Returns dict mapping tier -> paths exploitable by that tier.
        """
        result = {tier: [] for tier in AdversaryModeler.TIERS.keys()}

        for path, scoring in paths:
            for tier in AdversaryModeler.TIERS.keys():
                filtered = AdversaryModeler.filter_by_tier([(path, scoring)], tier)
                if filtered:
                    result[tier].append((path, scoring))

        return result


if __name__ == "__main__":
    print("[MOD-07] Attack Path Finder Examples\n")

    # Example scoring
    nodes = [
        {"id": "ATK-1", "type": "AttackerPosition", "name": "External"},
        {"id": "VUL-1", "type": "Weakness", "cvss_score": 8.5, "name": "Input Validation"},
        {"id": "AST-1", "type": "Asset", "sensitivity": "CRITICAL", "name": "Database"}
    ]

    edges = [
        {"src": "ATK-1", "dst": "VUL-1", "confidence": 0.9, "detection_probability": 0.2},
        {"src": "VUL-1", "dst": "AST-1", "confidence": 0.95, "detection_probability": 0.1}
    ]

    scoring = PathScorer.score_path(nodes, edges)
    print("Path Scoring Example:")
    print(f"  Exploitability: {scoring['exploitability']}")
    print(f"  Impact: {scoring['impact']}")
    print(f"  Probability: {scoring['probability']}")
    print(f"  Detectability: {scoring['detectability']}")
    print(f"  Overall Score: {scoring['overall_score']}/10")
    print()

    # Example adversary modeling
    print("Adversary Tier Capabilities:")
    for tier, info in AdversaryModeler.TIERS.items():
        print(f"  {tier}: {info['name']}")