"""
MISTCODER MOD-07 — Cypher Query Builder
Version 0.1.0 — Fluent query construction for Neo4j
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timezone


class CypherBuilder:
    """
    Fluent API for constructing Cypher queries without string concatenation.
    Prevents injection and improves readability.
    
    Usage:
        query = (CypherBuilder()
            .match("(n:Asset)")
            .where("n.sensitivity", "CRITICAL")
            .return_("n")
            .build())
    """

    def __init__(self):
        self.clauses = []
        self.params = {}
        self._param_counter = 0

    def _next_param(self, prefix: str = "p") -> str:
        """Generate unique parameter name"""
        self._param_counter += 1
        return f"{prefix}{self._param_counter}"

    def match(self, pattern: str) -> "CypherBuilder":
        """Add MATCH clause"""
        self.clauses.append(f"MATCH {pattern}")
        return self

    def where(self, property_path: str, operator: str, value: Any = None) -> "CypherBuilder":
        """Add WHERE clause with parameter binding"""
        param_name = self._next_param()
        
        if value is None:
            # Handle operators like 'IS NULL'
            self.clauses.append(f"WHERE {property_path} {operator}")
        else:
            self.params[param_name] = value
            self.clauses.append(f"WHERE {property_path} {operator} ${param_name}")
        
        return self

    def and_where(self, property_path: str, operator: str, value: Any = None) -> "CypherBuilder":
        """Add AND WHERE clause"""
        param_name = self._next_param()
        
        if value is None:
            self.clauses.append(f"AND {property_path} {operator}")
        else:
            self.params[param_name] = value
            self.clauses.append(f"AND {property_path} {operator} ${param_name}")
        
        return self

    def or_where(self, property_path: str, operator: str, value: Any = None) -> "CypherBuilder":
        """Add OR WHERE clause"""
        param_name = self._next_param()
        
        if value is None:
            self.clauses.append(f"OR {property_path} {operator}")
        else:
            self.params[param_name] = value
            self.clauses.append(f"OR {property_path} {operator} ${param_name}")
        
        return self

    def optional_match(self, pattern: str) -> "CypherBuilder":
        """Add OPTIONAL MATCH clause"""
        self.clauses.append(f"OPTIONAL MATCH {pattern}")
        return self

    def with_clause(self, *items: str) -> "CypherBuilder":
        """Add WITH clause for intermediate results"""
        self.clauses.append(f"WITH {', '.join(items)}")
        return self

    def return_(self, *items: str) -> "CypherBuilder":
        """Add RETURN clause"""
        self.clauses.append(f"RETURN {', '.join(items)}")
        return self

    def order_by(self, *items: str) -> "CypherBuilder":
        """Add ORDER BY clause"""
        self.clauses.append(f"ORDER BY {', '.join(items)}")
        return self

    def limit(self, count: int) -> "CypherBuilder":
        """Add LIMIT clause"""
        self.clauses.append(f"LIMIT {count}")
        return self

    def skip(self, count: int) -> "CypherBuilder":
        """Add SKIP clause"""
        self.clauses.append(f"SKIP {count}")
        return self

    def build(self) -> Dict[str, Any]:
        """Build final query dict with query string and parameters"""
        query = "\n".join(self.clauses)
        return {
            "query": query,
            "params": self.params
        }

    def build_query(self) -> str:
        """Build just the query string (for inspection)"""
        return "\n".join(self.clauses)

    def __str__(self) -> str:
        return self.build_query()


class AttackPathQueryBuilder:
    """
    High-level queries for attack path discovery.
    Builds complex Cypher queries for threat modeling.
    """

    @staticmethod
    def find_paths_from_attacker(
        attacker_id: str,
        target_id: str,
        max_length: int = 5,
        min_confidence: float = 0.0
    ) -> Dict[str, Any]:
        """
        Find all attack paths from attacker position to target asset.
        
        Returns paths where each edge has confidence >= min_confidence.
        """
        builder = CypherBuilder()
        
        p1 = builder._next_param("attacker")
        p2 = builder._next_param("target")
        p3 = builder._next_param("conf")
        
        builder.params[p1] = attacker_id
        builder.params[p2] = target_id
        builder.params[p3] = min_confidence
        
        return {
            "query": f"""
MATCH path = (attacker {{id: ${p1}}})
  -[rel*1..{max_length}]->
  (target {{id: ${p2}}})
WHERE ALL(r IN relationships(path) WHERE r.confidence IS NULL OR r.confidence >= ${p3})
RETURN 
  path,
  length(path) as steps,
  [n IN nodes(path) | n.id] as node_ids,
  [r IN relationships(path) | r.confidence] as confidences
ORDER BY steps ASC
LIMIT 100
            """.strip(),
            "params": builder.params
        }

    @staticmethod
    def find_reachable_assets(
        attacker_id: str,
        relationship_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Find all assets reachable from an attacker position.
        """
        builder = CypherBuilder()
        p1 = builder._next_param("attacker")
        builder.params[p1] = attacker_id
        
        rel_filter = ""
        if relationship_types:
            rel_types = "|".join(relationship_types)
            rel_filter = f"[:{rel_types}]"
        
        return {
            "query": f"""
MATCH (attacker {{id: ${p1}}})
MATCH (attacker)-[{rel_filter}*]->(asset)
WHERE asset.type IN ['Asset', 'DataStore', 'Credential', 'Capability']
RETURN DISTINCT
  asset.id as id,
  asset.name as name,
  asset.type as type,
  asset.sensitivity as sensitivity
ORDER BY asset.sensitivity DESC
            """.strip(),
            "params": builder.params
        }

    @staticmethod
    def find_vulnerability_chains(max_chain_length: int = 3) -> Dict[str, Any]:
        """
        Find chains of vulnerabilities where A must be exploited before B.
        """
        query = f"""
MATCH (v1:Weakness)
  -[:Precondition]->
  (v2:Weakness)
WHERE v2.type IN ['ConfirmedVuln', 'ProbableVuln']
RETURN
  v1.id as first_vuln,
  v1.name as first_name,
  v1.cvss_score as first_cvss,
  v2.id as second_vuln,
  v2.name as second_name,
  v2.cvss_score as second_cvss
ORDER BY (v1.cvss_score + v2.cvss_score) DESC
LIMIT 50
        """
        return {"query": query.strip(), "params": {}}

    @staticmethod
    def find_critical_assets() -> Dict[str, Any]:
        """
        Find all critical assets (highest sensitivity).
        """
        query = """
MATCH (asset:Asset)
WHERE asset.sensitivity = 'CRITICAL'
RETURN
  asset.id as id,
  asset.name as name,
  asset.type as type
ORDER BY asset.name
        """
        return {"query": query.strip(), "params": {}}

    @staticmethod
    def find_undefended_vulnerabilities() -> Dict[str, Any]:
        """
        Find vulnerabilities that are NOT protected by any mitigation.
        """
        query = """
MATCH (vuln:Weakness)
WHERE NOT (vuln)-[:Bypasses|ProtectedBy]->()
RETURN
  vuln.id as id,
  vuln.name as name,
  vuln.type as type,
  vuln.cvss_score as cvss
ORDER BY vuln.cvss_score DESC
LIMIT 50
        """
        return {"query": query.strip(), "params": {}}

    @staticmethod
    def compute_attack_surface() -> Dict[str, Any]:
        """
        Compute overall attack surface: count reachable assets from each attacker position.
        """
        query = """
MATCH (attacker:AttackerPosition)
MATCH (attacker)-[*]->(asset:Asset)
WITH attacker, COUNT(DISTINCT asset) as reachable_assets
RETURN
  attacker.id as position,
  attacker.name as position_name,
  reachable_assets,
  COUNT(DISTINCT asset) * 10 as surface_score
ORDER BY surface_score DESC
        """
        return {"query": query.strip(), "params": {}}

    @staticmethod
    def find_privilege_escalation_chains() -> Dict[str, Any]:
        """
        Find multi-step privilege escalation paths.
        Chains where a low-privilege attacker reaches high-privilege assets.
        """
        query = """
MATCH path = (low:AttackerPosition {name: 'AuthenticatedUser'})
  -[*1..4]->
  (high:Capability {sensitivity: 'CRITICAL'})
RETURN
  path,
  length(path) as steps,
  [n IN nodes(path) | n.name] as chain
ORDER BY steps ASC
LIMIT 20
        """
        return {"query": query.strip(), "params": {}}


class GraphStatisticsBuilder:
    """
    Queries for graph health and analytics.
    """

    @staticmethod
    def node_type_distribution() -> Dict[str, Any]:
        """Count nodes by type"""
        query = """
MATCH (n)
RETURN
  CASE 
    WHEN n:Asset THEN 'Asset'
    WHEN n:Weakness THEN 'Weakness'
    WHEN n:AttackerPosition THEN 'AttackerPosition'
    WHEN n:Mitigation THEN 'Mitigation'
    ELSE 'Other'
  END as type,
  COUNT(n) as count
ORDER BY count DESC
        """
        return {"query": query.strip(), "params": {}}

    @staticmethod
    def edge_type_distribution() -> Dict[str, Any]:
        """Count edges by type"""
        query = """
MATCH ()-[r]->()
RETURN
  type(r) as relationship_type,
  COUNT(r) as count
ORDER BY count DESC
        """
        return {"query": query.strip(), "params": {}}

    @staticmethod
    def graph_density() -> Dict[str, Any]:
        """Calculate graph density (actual edges / possible edges)"""
        query = """
MATCH (n)
WITH COUNT(n) as node_count
MATCH ()-[r]->()
WITH node_count, COUNT(r) as edge_count
RETURN
  node_count,
  edge_count,
  CASE 
    WHEN node_count * (node_count - 1) = 0 THEN 0
    ELSE ROUND(TOSTRING(100.0 * edge_count / (node_count * (node_count - 1))), 2)
  END as density_percent
        """
        return {"query": query.strip(), "params": {}}

    @staticmethod
    def most_connected_nodes(limit: int = 10) -> Dict[str, Any]:
        """Find nodes with most edges (both incoming and outgoing)"""
        query = f"""
MATCH (n)-[r]-(m)
WITH n, COUNT(DISTINCT r) as degree
RETURN
  n.id as id,
  n.name as name,
  n.type as type,
  degree
ORDER BY degree DESC
LIMIT {limit}
        """
        return {"query": query.strip(), "params": {}}


if __name__ == "__main__":
    # Test CypherBuilder
    print("[MOD-07] Cypher Query Builder Examples\n")

    # Example 1: Simple query
    q1 = (CypherBuilder()
          .match("(n:Asset)")
          .where("n.sensitivity", "=", "CRITICAL")
          .return_("n.id", "n.name")
          .limit(10)
          .build())
    
    print("Example 1: Find critical assets")
    print(q1["query"])
    print()

    # Example 2: Complex query with multiple conditions
    q2 = (CypherBuilder()
          .match("(vuln:Weakness)")
          .where("vuln.cvss_score", ">", 8.0)
          .and_where("vuln.type", "=", "ConfirmedVuln")
          .optional_match("(vuln)-[:Exploits]->(asset:Asset)")
          .return_("vuln.id", "vuln.name", "asset.name")
          .order_by("vuln.cvss_score DESC")
          .build())
    
    print("Example 2: High-CVSS confirmed vulns with target assets")
    print(q2["query"])
    print()

    # Example 3: Attack path finder
    q3 = AttackPathQueryBuilder.find_paths_from_attacker(
        attacker_id="ATK-EXTERNAL",
        target_id="AST-CUSTOMER-DB",
        max_length=5,
        min_confidence=0.7
    )
    
    print("Example 3: Find attack paths")
    print(q3["query"])
    print()

    # Example 4: Statistics
    q4 = GraphStatisticsBuilder.node_type_distribution()
    print("Example 4: Node type distribution")
    print(q4["query"])