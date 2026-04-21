 MOD-07 Technical Specification — Knowledge Graph Integration

**Module ID:** MSTC-MOD-07  
**Layer:** 3 — Reasoning Core Support  
**Status:** Phase 3 Implementation  
**Version:** 0.1.0  

---

## 1. Overview

The Knowledge Graph Integration module provides a scalable, queryable representation of the complete threat landscape of a software system. 

**Current State (v0.1.0):** In-memory GraphStore  
**Target State (v0.1.0→v0.2.0):** Neo4j backend with fallback in-memory  

---

## 2. Architecture

### 2.1 Dual-Backend Design

┌─────────────────────────────────────────┐ │ Knowledge Graph Interface (Abstract) │ ├─────────────────────────────────────────┤ │ │ ├─────────────────────┬───────────────────┤ │ In-Memory Backend │ Neo4j Backend │ │ (Development) │ (Production) │ │ ✓ No external deps │ ✓ Scales to 1M+ │ │ ✗ Single-machine │ ✗ Requires setup │ └─────────────────────┴───────────────────┘

Code

### 2.2 Data Model

**Node Types:**
Asset ├── DataStore (DB, file, cache, secret store) ├── Credential (API key, password, token) ├── Capability (privileged operation) └── ExternalSystem (downstream service)

Weakness ├── ConfirmedVuln (verified, exploitable) ├── ProbableVuln (high-confidence candidate) └── HypotheticalVuln (reasoning-derived)

TrustBoundary ├── ProcessBoundary ├── NetworkBoundary └── PrivilegeBoundary

AttackerPosition ├── External (unauthenticated internet) ├── AuthenticatedUser (legitimate user) ├── InternalNetwork (on internal LAN) └── CodeExecution (arbitrary code)

Mitigation ├── Authentication ├── Authorization ├── Sanitization ├── Encryption └── RateLimit

Code

**Edge Types:**
Exploits # Weakness → Asset Enables # Weakness → AttackerPosition Bypasses # Weakness → Mitigation Precondition # Weakness → Weakness (A must be exploited before B) Amplifies # Weakness → Weakness (A makes B more severe) ProtectedBy # Asset → Mitigation Crosses # AttackerPosition → TrustBoundary

Code

---

## 3. Neo4j Schema

### 3.1 Cypher Node Creation Examples

```cypher
-- Create asset node
CREATE (asset:Asset {
  id: 'AST-001',
  name: 'customer_database',
  type: 'DataStore',
  sensitivity: 'CRITICAL',
  created_at: timestamp()
})

-- Create weakness node
CREATE (vuln:Weakness {
  id: 'VUL-001',
  name: 'SQL Injection in payment endpoint',
  type: 'ConfirmedVuln',
  cvss_score: 8.9,
  cwe_id: 'CWE-89',
  created_at: timestamp()
})

-- Create relationship
CREATE (vuln)-[:Exploits {confidence: 0.95, effort: 'low'}]->(asset)
3.2 Query Examples
Cypher
-- Find all attack paths from external attacker to customer_database
MATCH path = (attacker:AttackerPosition {name: 'External'})
  -[*]->
  (asset:Asset {name: 'customer_database'})
WHERE ALL(rel IN relationships(path) WHERE rel.confidence > 0.7)
RETURN path, length(path) as steps
ORDER BY steps ASC
LIMIT 10

-- Find reachable assets from a given attacker position
MATCH (attacker:AttackerPosition {name: 'External'})
  -[rel:Enables|Exploits]->
  (pos:AttackerPosition)
OPTIONAL MATCH (pos)-[rel2:Exploits]->(asset:Asset)
RETURN DISTINCT asset
ORDER BY asset.sensitivity DESC

-- Find cascading vulnerabilities (A enables B enables C)
MATCH (v1:Weakness)
  -[:Precondition]->(v2:Weakness)
  -[:Precondition]->(v3:Weakness)
  -[:Exploits]->(asset:Asset)
RETURN v1, v2, v3, asset
LIMIT 5
4. Implementation Milestones
Phase 3.1 — Core Backend (Week 1)
 Abstract GraphStore interface
 Neo4j connection pooling
 Node/edge CRUD operations
 Transaction support
Phase 3.2 — Query Engine (Week 2)
 Cypher query builder
 Path-finding algorithms
 Reachability analysis
 Graph statistics
Phase 3.3 — Integration (Week 3)
 Ingest MOD-02 findings into graph
 Ingest MOD-04 attack paths
 Build threat knowledge graph automatically
 Persist and load snapshots
Phase 3.4 — Performance & Testing (Week 4)
 Benchmark queries on 100K+ nodes
 Implement caching layer
 Load testing (1M+ nodes)
 Full test coverage (50+ tests)
5. API Examples
Python
# Initialize
from knowledge_graph import KnowledgeGraph, NeoBackend

backend = NeoBackend(uri="bolt://localhost:7687", user="neo4j", password="...")
kg = KnowledgeGraph(backend)

# Add nodes
asset = kg.add_asset("AST-001", "customer_db", type="DataStore", sensitivity="CRITICAL")
vuln = kg.add_weakness("VUL-001", "SQL Injection", type="ConfirmedVuln", cvss=8.9)

# Create relationships
kg.add_relationship(vuln, asset, "Exploits", confidence=0.95)

# Query
paths = kg.find_attack_paths(
    start_position="External",
    target_asset="customer_db",
    max_length=5,
    min_confidence=0.7
)

# Export
kg.export_to_json("graph_snapshot.json")
kg.export_threat_report("threat_report.html")
6. Performance Targets
Operation	Target	Notes
Add 1000 nodes	< 5s	Batch operation
Find top-10 paths (100K nodes)	< 10s	With caching
Full reachability analysis	< 30s	From one attacker position
Graph consistency check	< 5s	Validate integrity
Export to JSON (1M nodes)	< 60s	Compressed
7. Fallback Strategy
If Neo4j is unavailable:

KnowledgeGraph automatically uses in-memory backend
Performance limited to system RAM (~100K nodes)
All queries still work (via sequential search)
Warning logged at startup
8. Testing Strategy
Python
# test_knowledge_graph.py structure

class TestGraphStore(unittest.TestCase):
    """Abstract interface tests — pass for both backends"""

class TestNeoBackend(unittest.TestCase):
    """Neo4j-specific tests"""
    
class TestInMemoryBackend(unittest.TestCase):
    """In-memory fallback tests"""

class TestAttackPathQueries(unittest.TestCase):
    """High-level query tests"""
MISTCODER Research Initiative — MOD-07 Specification v0.1.0

Code

### **2.2 Create the Neo4j Python implementation**

```bash
touch modules/knowledge_graph/src/neo4j_backend.py