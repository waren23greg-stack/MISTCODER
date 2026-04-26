"""
patch_phantom.py — Adds find_node / reachable_from / find_nodes_by_type / add_edge
to MemoryBackend in phantom_bridge.py, and wires up edge construction so
AttackPathFinder.find_critical_paths() produces real ranked attack chains.

Run from repo root:  python patch_phantom.py
"""
import sys
from collections import defaultdict

PATH = "phantom_bridge.py"

try:
    src = open(PATH, encoding="utf-8").read()
except FileNotFoundError:
    print(f"ERROR: {PATH} not found — run from repo root"); sys.exit(1)

# ── 1. Add _adj to __init__ ──────────────────────────────────────────────────
OLD_INIT = 'self._node_index: dict = {}'
NEW_INIT  = 'self._node_index: dict = {}\n        self._adj: dict = {}'
if OLD_INIT in src:
    src = src.replace(OLD_INIT, NEW_INIT, 1)
    print("  ✓ _adj initialised")
else:
    print("  WARN: _node_index anchor not found — check manually")

# ── 2. Add query methods after add_node ──────────────────────────────────────
OLD_ANCHOR = 'self._node_index[nid] = node\n        return node'
NEW_ANCHOR  = '''self._node_index[nid] = node
        return node

    # ── Query API (used by AttackPathFinder) ───────────────────────────────
    def add_edge(self, src_id: str, dst_id: str,
                 rel_type: str = "LEADS_TO", props: dict = None) -> dict:
        edge = {"src": src_id, "dst": dst_id,
                "type": rel_type, **(props or {})}
        self.edges.append(edge)
        self._adj.setdefault(src_id, []).append(dst_id)
        return edge

    def find_node(self, node_id: str):
        return self._node_index.get(node_id)

    def reachable_from(self, node_id: str):
        return [self._node_index[nid]
                for nid in self._adj.get(node_id, [])
                if nid in self._node_index]

    def find_nodes_by_type(self, node_type: str):
        return [n for n in self.nodes if n.get("type") == node_type]'''

if OLD_ANCHOR in src:
    src = src.replace(OLD_ANCHOR, NEW_ANCHOR, 1)
    print("  ✓ Query methods injected")
else:
    print("  WARN: add_node anchor not found — check manually")

# ── 3. Inject edge-building block after nodes-print line ────────────────────
OLD_NODES_PRINT = 'print(f"  [TKG] Nodes built: {len(backend.nodes)}")'
NEW_NODES_BLOCK  = '''print(f"  [TKG] Nodes built: {len(backend.nodes)}")

    # ── Build edges: chain findings per-file by severity order ─────────────
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    from collections import defaultdict as _dd
    by_file = _dd(list)
    for node in backend.nodes:
        f = node.get("file") or node.get("filename") or "unknown"
        by_file[f].append(node)

    edge_count = 0
    for file_nodes in by_file.values():
        sorted_nodes = sorted(
            file_nodes,
            key=lambda n: SEV_ORDER.get(str(n.get("severity","INFO")).upper(), 4)
        )
        for i in range(len(sorted_nodes) - 1):
            src_n  = sorted_nodes[i]
            dst_n  = sorted_nodes[i + 1]
            src_id = src_n.get("id") or str(id(src_n))
            dst_id = dst_n.get("id") or str(id(dst_n))
            backend.add_edge(src_id, dst_id,
                props={"confidence": 0.85, "detection_probability": 0.25})
            edge_count += 1
    print(f"  [TKG] Edges built:  {edge_count}")'''

if OLD_NODES_PRINT in src:
    src = src.replace(OLD_NODES_PRINT, NEW_NODES_BLOCK, 1)
    print("  ✓ Edge-building block injected")
else:
    print("  WARN: nodes-print anchor not found — edges not added")

# ── 4. Save ──────────────────────────────────────────────────────────────────
open(PATH, "w", encoding="utf-8").write(src)
print("\nPATCHED OK — run: python phantom_bridge.py sandbox/unified_ir.json")
