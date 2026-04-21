"""
MISTCODER MOD-08 — Callgraph Builder
Version 0.1.0 — Function call relationship analysis
"""

from typing import Dict, List, Set, Optional, Tuple, Any
from collections import defaultdict, deque


class CallNode:
    """Represents a function in the callgraph"""

    def __init__(self, func_id: str, name: str, address: str, size: int = 0):
        self.func_id = func_id
        self.name = name
        self.address = address
        self.size = size
        self.callers: Set[str] = set()      # Functions that call this
        self.callees: Set[str] = set()      # Functions this calls
        self.is_recursive = False
        self.is_external = False            # e.g., libc function
        self.call_count = 0

    def add_caller(self, caller_id: str) -> None:
        """Register a caller"""
        self.callers.add(caller_id)

    def add_callee(self, callee_id: str) -> None:
        """Register a callee"""
        self.callees.add(callee_id)

    def to_dict(self) -> Dict:
        return {
            "id": self.func_id,
            "name": self.name,
            "address": self.address,
            "size": self.size,
            "callers": list(self.callers),
            "callees": list(self.callees),
            "is_recursive": self.is_recursive,
            "is_external": self.is_external,
            "call_count": self.call_count
        }


class CallgraphBuilder:
    """
    Builds a callgraph from binary analysis results.
    Identifies function relationships and call chains.
    """

    def __init__(self):
        self.nodes: Dict[str, CallNode] = {}
        self.edges: List[Tuple[str, str]] = []
        self._recursion_depth = 0

    def add_function(self, func_id: str, name: str, address: str, size: int = 0) -> CallNode:
        """Add a function node to the callgraph"""
        if func_id not in self.nodes:
            node = CallNode(func_id, name, address, size)
            self.nodes[func_id] = node
        return self.nodes[func_id]

    def add_call(self, caller_id: str, callee_id: str, call_site: str = "", count: int = 1) -> bool:
        """
        Add a call edge (caller -> callee).
        Returns True if edge added, False if already exists.
        """
        if caller_id not in self.nodes or callee_id not in self.nodes:
            return False

        # Check if edge already exists
        if callee_id in self.nodes[caller_id].callees:
            return False

        # Add edge
        self.nodes[caller_id].add_callee(callee_id)
        self.nodes[callee_id].add_caller(caller_id)
        self.nodes[callee_id].call_count += count

        self.edges.append((caller_id, callee_id))
        return True

    def mark_external(self, func_id: str) -> None:
        """Mark a function as external (e.g., library function)"""
        if func_id in self.nodes:
            self.nodes[func_id].is_external = True

    def detect_recursion(self) -> Dict[str, bool]:
        """
        Detect recursive functions using DFS.
        Returns dict mapping func_id -> is_recursive.
        """
        recursion_map = {}
        visited = set()
        rec_stack = set()

        def dfs(node_id: str) -> bool:
            visited.add(node_id)
            rec_stack.add(node_id)

            node = self.nodes.get(node_id)
            if not node:
                return False

            is_recursive = False
            for callee_id in node.callees:
                if callee_id not in visited:
                    if dfs(callee_id):
                        is_recursive = True
                elif callee_id in rec_stack:
                    # Found cycle
                    is_recursive = True

            rec_stack.remove(node_id)
            if is_recursive:
                self.nodes[node_id].is_recursive = True
            recursion_map[node_id] = is_recursive
            return is_recursive

        # Check all functions
        for func_id in self.nodes:
            if func_id not in visited:
                dfs(func_id)

        return recursion_map

    def find_entry_points(self) -> List[str]:
        """
        Find entry points (functions with no callers, typically main/entry).
        """
        return [
            func_id for func_id in self.nodes
            if not self.nodes[func_id].callers and not self.nodes[func_id].is_external
        ]

    def find_leaf_functions(self) -> List[str]:
        """
        Find leaf functions (functions that don't call anything).
        """
        return [
            func_id for func_id in self.nodes
            if not self.nodes[func_id].callees
        ]

    def find_call_chains(self, start_id: str, max_depth: int = 10) -> List[List[str]]:
        """
        Find all call chains starting from a function using DFS.
        """
        chains = []

        def dfs(node_id: str, path: List[str], visited: Set[str], depth: int) -> None:
            if depth >= max_depth:
                return

            node = self.nodes.get(node_id)
            if not node or not node.callees:
                # Reached a leaf
                chains.append(path)
                return

            for callee_id in node.callees:
                if callee_id not in visited:  # Avoid infinite recursion
                    new_visited = visited | {callee_id}
                    dfs(callee_id, path + [callee_id], new_visited, depth + 1)

        # Start DFS
        initial_visited = {start_id}
        node = self.nodes.get(start_id)
        if node:
            for callee_id in node.callees:
                dfs(callee_id, [start_id, callee_id], initial_visited | {callee_id}, 1)

        return chains

    def find_reachable_functions(self, start_id: str) -> Set[str]:
        """
        Find all functions reachable from a given function.
        """
        reachable = set()
        queue = deque([start_id])
        visited = {start_id}

        while queue:
            func_id = queue.popleft()
            node = self.nodes.get(func_id)
            if not node:
                continue

            for callee_id in node.callees:
                if callee_id not in visited:
                    visited.add(callee_id)
                    reachable.add(callee_id)
                    queue.append(callee_id)

        return reachable

    def get_call_depth(self, func_id: str) -> int:
        """
        Get the maximum depth from this function to a leaf.
        """
        node = self.nodes.get(func_id)
        if not node or not node.callees:
            return 0

        max_depth = 0
        for callee_id in node.callees:
            depth = 1 + self.get_call_depth(callee_id)
            max_depth = max(max_depth, depth)

        return max_depth

    def get_stats(self) -> Dict[str, Any]:
        """Get callgraph statistics"""
        recursive_count = sum(1 for n in self.nodes.values() if n.is_recursive)
        external_count = sum(1 for n in self.nodes.values() if n.is_external)
        leaf_count = len(self.find_leaf_functions())
        entry_count = len(self.find_entry_points())

        return {
            "total_functions": len(self.nodes),
            "total_calls": len(self.edges),
            "recursive_functions": recursive_count,
            "external_functions": external_count,
            "leaf_functions": leaf_count,
            "entry_points": entry_count,
            "avg_call_depth": self._calculate_avg_depth()
        }

    def _calculate_avg_depth(self) -> float:
        """Calculate average call depth"""
        if not self.nodes:
            return 0.0

        depths = [self.get_call_depth(func_id) for func_id in self.find_entry_points()]
        if not depths:
            return 0.0

        return sum(depths) / len(depths)

    def to_dict(self) -> Dict:
        """Export callgraph as dict"""
        return {
            "nodes": [node.to_dict() for node in self.nodes.values()],
            "edges": [{"src": src, "dst": dst} for src, dst in self.edges],
            "stats": self.get_stats()
        }


class DangerousCallAnalyzer:
    """
    Analyzes callgraph for dangerous call chains.
    Identifies paths that reach dangerous functions (eval, system, etc.).
    """

    DANGEROUS_FUNCTIONS = {
        "system", "exec", "execl", "execle", "execlp", "execv", "execve", "execvp",
        "fork", "vfork", "clone", "popen",
        "eval", "exec", "compile", "pickle.loads",
        "dlopen", "dlsym",
        "mmap", "mprotect",
        "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA", "ShellExecuteW",
    }

    def __init__(self, callgraph: CallgraphBuilder):
        self.callgraph = callgraph

    def find_dangerous_paths(self, start_func: str) -> List[Dict[str, Any]]:
        """
        Find all call chains from start_func that reach dangerous functions.
        """
        dangerous_paths = []
        chains = self.callgraph.find_call_chains(start_func, max_depth=8)

        for chain in chains:
            # Check if any function in chain is dangerous
            for func_id in chain:
                node = self.callgraph.nodes.get(func_id)
                if node and (node.name in self.DANGEROUS_FUNCTIONS or
                            any(danger in node.name.lower() for danger in self.DANGEROUS_FUNCTIONS)):
                    dangerous_paths.append({
                        "chain": chain,
                        "dangerous_function": func_id,
                        "depth": len(chain),
                        "severity": self._calculate_severity(chain)
                    })
                    break

        return dangerous_paths

    def _calculate_severity(self, chain: List[str]) -> str:
        """Calculate severity based on chain length and functions involved"""
        if len(chain) >= 5:
            return "CRITICAL"
        elif len(chain) >= 3:
            return "HIGH"
        elif len(chain) >= 2:
            return "MEDIUM"
        else:
            return "LOW"

    def get_tainted_functions(self) -> List[str]:
        """
        Find functions that can transitively reach dangerous functions.
        """
        tainted = set()

        for func_id in self.callgraph.nodes:
            reachable = self.callgraph.find_reachable_functions(func_id)
            for reachable_id in reachable:
                node = self.callgraph.nodes.get(reachable_id)
                if node and (node.name in self.DANGEROUS_FUNCTIONS or
                            any(d in node.name.lower() for d in self.DANGEROUS_FUNCTIONS)):
                    tainted.add(func_id)
                    break

        return list(tainted)


if __name__ == "__main__":
    print("[MOD-08] Callgraph Builder Example\n")

    # Create example callgraph
    cg = CallgraphBuilder()

    # Add functions
    cg.add_function("FN001", "main", "0x400000", 256)
    cg.add_function("FN002", "process_input", "0x400100", 128)
    cg.add_function("FN003", "validate", "0x400200", 64)
    cg.add_function("FN004", "system", "0x7f0000", 50)

    # Add calls
    cg.add_call("FN001", "FN002")
    cg.add_call("FN002", "FN003")
    cg.add_call("FN002", "FN004")

    # Mark external
    cg.mark_external("FN004")

    # Analyze
    print("Entry points:", cg.find_entry_points())
    print("Leaf functions:", cg.find_leaf_functions())
    print("Call chains from main:", cg.find_call_chains("FN001"))
    print("Stats:", cg.get_stats())
    print()

    # Dangerous path analysis
    analyzer = DangerousCallAnalyzer(cg)
    dangerous = analyzer.find_dangerous_paths("FN001")
    print("Dangerous paths:", dangerous)