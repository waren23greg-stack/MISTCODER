"""
MISTCODER MOD-07 — Neo4j Knowledge Graph Backend
Version 0.1.0 — Initial implementation with fallback support
"""

import json
import os
from typing import Optional, List, Dict, Tuple, Any
from datetime import datetime, timezone
from abc import ABC, abstractmethod


# ---------------------------------------------------------------------------
# Abstract backend interface
# ---------------------------------------------------------------------------

class GraphBackend(ABC):
    """Abstract interface for graph backends (Neo4j, in-memory, etc.)"""

    @abstractmethod
    def add_node(self, node_id: str, node_type: str, name: str, properties: dict) -> bool:
        """Add a node to the graph"""
        pass

    @abstractmethod
    def add_edge(self, src_id: str, dst_id: str, edge_type: str, properties: dict) -> bool:
        """Add a directed edge"""
        pass

    @abstractmethod
    def find_node(self, node_id: str) -> Optional[dict]:
        """Retrieve a single node"""
        pass

    @abstractmethod
    def find_nodes_by_type(self, node_type: str) -> List[dict]:
        """Find all nodes of a given type"""
        pass

    @abstractmethod
    def find_paths(self, start_id: str, end_id: str, max_length: int = 10) -> List[List[str]]:
        """Find all paths between two nodes"""
        pass

    @abstractmethod
    def reachable_from(self, start_id: str, relationship_types: Optional[List[str]] = None) -> List[dict]:
        """Find all nodes reachable from start_id"""
        pass

    @abstractmethod
    def get_stats(self) -> dict:
        """Return graph statistics"""
        pass


# ---------------------------------------------------------------------------
# Neo4j Backend (requires neo4j package)
# ---------------------------------------------------------------------------

class NeoBackend(GraphBackend):
    """
    Neo4j backend for MISTCODER Knowledge Graph.
    Supports large-scale graphs (1M+ nodes).
    
    Requirements:
        pip install neo4j
    
    Usage:
        backend = NeoBackend(
            uri="bolt://localhost:7687",
            user="neo4j",
            password="your_password"
        )
    """

    def __init__(self, uri: str = "bolt://localhost:7687", 
                 user: str = "neo4j", 
                 password: str = "password",
                 database: str = "neo4j"):
        try:
            from neo4j import GraphDatabase
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            self.database = database
            self._verify_connection()
            print(f"[MOD-07] Neo4j backend initialized at {uri}")
        except ImportError:
            raise ImportError(
                "neo4j package not found. Install with: pip install neo4j"
            )
        except Exception as e:
            raise ConnectionError(
                f"Failed to connect to Neo4j at {uri}: {e}\n"
                f"Ensure Neo4j is running and credentials are correct."
            )

    def _verify_connection(self):
        """Test connection to Neo4j"""
        try:
            with self.driver.session(database=self.database) as session:
                session.run("RETURN 1")
        except Exception as e:
            raise ConnectionError(f"Neo4j connection failed: {e}")

    def add_node(self, node_id: str, node_type: str, name: str, properties: dict) -> bool:
        """Add a node to Neo4j"""
        query = f"""
            CREATE (n:{node_type} {{
                id: $id,
                name: $name,
                created_at: timestamp()
            }})
            SET n += $props
            RETURN n
        """
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(query, id=node_id, name=name, props=properties)
                return result.single() is not None
        except Exception as e:
            print(f"[MOD-07] Error adding node {node_id}: {e}")
            return False

    def add_edge(self, src_id: str, dst_id: str, edge_type: str, properties: dict) -> bool:
        """Add a directed edge in Neo4j"""
        query = f"""
            MATCH (src {{id: $src_id}})
            MATCH (dst {{id: $dst_id}})
            CREATE (src)-[r:{edge_type} {{
                type: $edge_type,
                created_at: timestamp()
            }}]->(dst)
            SET r += $props
            RETURN r
        """
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(
                    query,
                    src_id=src_id,
                    dst_id=dst_id,
                    edge_type=edge_type,
                    props=properties
                )
                return result.single() is not None
        except Exception as e:
            print(f"[MOD-07] Error adding edge {src_id}->{dst_id}: {e}")
            return False

    def find_node(self, node_id: str) -> Optional[dict]:
        """Find a node by ID"""
        query = "MATCH (n {id: $id}) RETURN n"
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(query, id=node_id)
                record = result.single()
                return dict(record['n']) if record else None
        except Exception as e:
            print(f"[MOD-07] Error finding node {node_id}: {e}")
            return None

    def find_nodes_by_type(self, node_type: str) -> List[dict]:
        """Find all nodes of a given type"""
        query = f"MATCH (n:{node_type}) RETURN n LIMIT 10000"
        try:
            with self.driver.session(database=self.database) as session:
                results = session.run(query)
                return [dict(record['n']) for record in results]
        except Exception as e:
            print(f"[MOD-07] Error finding nodes of type {node_type}: {e}")
            return []

    def find_paths(self, start_id: str, end_id: str, max_length: int = 10) -> List[List[str]]:
        """Find all paths between two nodes using BFS in Cypher"""
        query = """
            MATCH path = (start {id: $start_id})
                -[*1..` + str(max_length) + `]->
                (end {id: $end_id})
            RETURN [n IN nodes(path) | n.id] as path_ids
            LIMIT 100
        """
        try:
            with self.driver.session(database=self.database) as session:
                results = session.run(query, start_id=start_id, end_id=end_id)
                return [record['path_ids'] for record in results]
        except Exception as e:
            print(f"[MOD-07] Error finding paths: {e}")
            return []

    def reachable_from(self, start_id: str, 
                      relationship_types: Optional[List[str]] = None) -> List[dict]:
        """Find all reachable nodes from start_id"""
        rel_filter = ""
        if relationship_types:
            rel_types = "|".join(relationship_types)
            rel_filter = f"[:{rel_types}]"

        query = f"""
            MATCH (start {{id: $start_id}})
            MATCH (start)-[{rel_filter}*]->(reachable)
            RETURN DISTINCT reachable
            LIMIT 10000
        """
        try:
            with self.driver.session(database=self.database) as session:
                results = session.run(query, start_id=start_id)
                return [dict(record['reachable']) for record in results]
        except Exception as e:
            print(f"[MOD-07] Error computing reachability: {e}")
            return []

    def get_stats(self) -> dict:
        """Get graph statistics"""
        query = """
            MATCH (n)
            WITH count(n) as nodes
            MATCH ()-[r]->()
            RETURN nodes, count(r) as edges
        """
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(query).single()
                return {
                    "node_count": result['nodes'],
                    "edge_count": result['edges'],
                    "backend": "Neo4j",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
        except Exception as e:
            print(f"[MOD-07] Error getting stats: {e}")
            return {"error": str(e)}

    def close(self):
        """Close connection"""
        self.driver.close()


# ---------------------------------------------------------------------------
# In-Memory Fallback Backend (no external dependencies)
# ---------------------------------------------------------------------------

class InMemoryBackend(GraphBackend):
    """
    In-memory fallback backend for MISTCODER Knowledge Graph.
    Used when Neo4j is unavailable. Suitable for graphs up to ~100K nodes.
    
    Advantages:
        - No external dependencies
        - Perfect for development and testing
        - Full Python compatibility
    
    Disadvantages:
        - Single-machine only
        - Limited to available RAM
        - No persistence
    """

    def __init__(self):
        self.nodes: Dict[str, dict] = {}
        self.edges: Dict[Tuple[str, str], dict] = {}
        self.node_types: Dict[str, set] = {}
        print("[MOD-07] In-memory backend initialized (development mode)")

    def add_node(self, node_id: str, node_type: str, name: str, properties: dict) -> bool:
        """Add a node to in-memory graph"""
        self.nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "name": name,
            "properties": properties,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        if node_type not in self.node_types:
            self.node_types[node_type] = set()
        self.node_types[node_type].add(node_id)
        return True

    def add_edge(self, src_id: str, dst_id: str, edge_type: str, properties: dict) -> bool:
        """Add an edge to in-memory graph"""
        if src_id not in self.nodes or dst_id not in self.nodes:
            return False
        key = (src_id, dst_id)
        self.edges[key] = {
            "src": src_id,
            "dst": dst_id,
            "type": edge_type,
            "properties": properties,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        return True

    def find_node(self, node_id: str) -> Optional[dict]:
        """Find a node by ID"""
        return self.nodes.get(node_id)

    def find_nodes_by_type(self, node_type: str) -> List[dict]:
        """Find all nodes of a given type"""
        return [self.nodes[nid] for nid in self.node_types.get(node_type, set())]

    def find_paths(self, start_id: str, end_id: str, max_length: int = 10) -> List[List[str]]:
        """Find all paths using DFS"""
        if start_id not in self.nodes or end_id not in self.nodes:
            return []

        paths = []
        stack = [(start_id, [start_id])]

        while stack:
            current, path = stack.pop()
            if current == end_id:
                paths.append(path)
                continue
            if len(path) >= max_length:
                continue
            for (src, dst), edge in self.edges.items():
                if src == current and dst not in path:
                    stack.append((dst, path + [dst]))

        return paths

    def reachable_from(self, start_id: str,
                      relationship_types: Optional[List[str]] = None) -> List[dict]:
        """Find all reachable nodes from start_id"""
        if start_id not in self.nodes:
            return []

        reachable = set()
        queue = [start_id]

        while queue:
            current = queue.pop(0)
            for (src, dst), edge in self.edges.items():
                if src == current:
                    if relationship_types is None or edge["type"] in relationship_types:
                        if dst not in reachable:
                            reachable.add(dst)
                            queue.append(dst)

        return [self.nodes[nid] for nid in reachable]

    def get_stats(self) -> dict:
        """Return graph statistics"""
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "backend": "In-Memory",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


# ---------------------------------------------------------------------------
# Auto-selecting wrapper
# ---------------------------------------------------------------------------

def create_backend(prefer_neo4j: bool = True) -> GraphBackend:
    """
    Create the best available backend.
    
    Tries Neo4j first if prefer_neo4j=True, falls back to in-memory.
    """
    if prefer_neo4j:
        try:
            return NeoBackend()
        except Exception as e:
            print(f"[MOD-07] Neo4j unavailable ({type(e).__name__}), using in-memory backend")
            return InMemoryBackend()
    else:
        return InMemoryBackend()


if __name__ == "__main__":
    # Demo script
    backend = create_backend(prefer_neo4j=False)

    print("\n[MOD-07] Creating sample graph...")

    # Add nodes
    backend.add_node("AST-001", "Asset", "customer_db", {"sensitivity": "CRITICAL"})
    backend.add_node("VUL-001", "Weakness", "SQL Injection", {"cvss": 8.9})
    backend.add_node("ATK-001", "AttackerPosition", "External", {})

    # Add edges
    backend.add_edge("ATK-001", "VUL-001", "Exploits", {"confidence": 0.9})
    backend.add_edge("VUL-001", "AST-001", "Exploits", {"confidence": 0.95})

    # Query
    print(f"\nStats: {backend.get_stats()}")
    print(f"Reachable from External: {backend.reachable_from('ATK-001')}")
    print(f"Paths from External to customer_db: {backend.find_paths('ATK-001', 'AST-001')}")