"""
MISTCODER — PHANTOM Engine  v1.0.0
Connects: UnifiedIR → ThreatKGBuilder → AttackPathFinder → Reasoner → Report

This is STEP 3 of the build plan.
It is the spine that connects every module you already built:
  modules/knowledge_graph/src/threat_kg_builder.py
  modules/knowledge_graph/src/attack_path_finder.py
  modules/reasoning/src/attack_path_reasoning.py
  modules/reasoning/src/explainability_chains.py
  modules/reasoning/src/vulnerability_discovery.py
"""
from __future__ import annotations
import sys, os, json, pathlib, datetime
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

ROOT = pathlib.Path(__file__).parent.parent.parent.parent   # repo root
sys.path.insert(0, str(ROOT))

# ── Attack path data model ───────────────────────────────────────────────────
@dataclass
class AttackPath:
    title:       str
    risk_score:  float
    nodes:       List[str]       = field(default_factory=list)
    cwes:        List[str]       = field(default_factory=list)
    explanation: str             = ""
    remediation: str             = ""
    confidence:  str             = "MEDIUM"   # LOW / MEDIUM / HIGH
    tactics:     List[str]       = field(default_factory=list)  # MITRE ATT&CK
    meta:        Dict[str, Any]  = field(default_factory=dict)

    @property
    def score(self):
        return round(self.risk_score, 2)

    @property
    def steps(self):
        return self.nodes


# ── TKG node + edge ─────────────────────────────────────────────────────────
@dataclass
class TKGNode:
    id:       str
    kind:     str         # TAINT_SOURCE | TAINT_SINK | FUNCTION | SECRET | CRYPTO_ISSUE
    label:    str
    severity: str = "INFO"
    file:     str = ""
    line:     int = 0
    cwe:      str = ""
    meta:     Dict[str, Any] = field(default_factory=dict)

@dataclass
class TKGEdge:
    src:    str
    dst:    str
    rel:    str           # FLOWS_TO | CALLS | USES | EXPOSES


class ThreatKG:
    """In-memory Threat Knowledge Graph."""
    def __init__(self):
        self.nodes: Dict[str, TKGNode] = {}
        self.edges: List[TKGEdge]      = []

    def add_node(self, node: TKGNode):
        self.nodes[node.id] = node

    def add_edge(self, edge: TKGEdge):
        self.edges.append(edge)

    def neighbours(self, node_id: str) -> List[str]:
        return [e.dst for e in self.edges if e.src == node_id]

    def predecessors(self, node_id: str) -> List[str]:
        return [e.src for e in self.edges if e.dst == node_id]

    def nodes_by_kind(self, kind: str) -> List[TKGNode]:
        return [n for n in self.nodes.values() if n.kind == kind]

    def stats(self):
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "sources": len(self.nodes_by_kind("TAINT_SOURCE")),
            "sinks":   len(self.nodes_by_kind("TAINT_SINK")),
            "secrets": len(self.nodes_by_kind("SECRET")),
            "crypto":  len(self.nodes_by_kind("CRYPTO_ISSUE")),
        }


# ── IR → TKG builder ─────────────────────────────────────────────────────────
class PhantomTKGBuilder:
    """
    Builds ThreatKG from UnifiedIR findings.
    Falls back to raw findings list if unified_ir dict is unavailable.
    """

    def build(self, unified_ir) -> ThreatKG:
        tkg = ThreatKG()

        # unified_ir can be a dict (from ir_bridge) or a list of finding objects
        findings = []
        if isinstance(unified_ir, dict):
            findings = unified_ir.get("findings", [])
        elif isinstance(unified_ir, list):
            findings = unified_ir

        for i, f in enumerate(findings):
            # Normalise finding (dataclass or dict)
            def g(key, *alts):
                if isinstance(f, dict):
                    for k in [key] + list(alts): 
                        if k in f: return f[k]
                    return ""
                for k in [key] + list(alts):
                    if hasattr(f, k): return getattr(f, k)
                return ""

            fid      = f"finding_{i}"
            kind     = self._infer_kind(g("finding_type", "type", "kind"), g("description", "message"))
            severity = g("severity", "sev") or "INFO"
            label    = g("description", "message", "title") or f"Finding {i}"
            cwe      = g("cwe", "cwe_id") or ""
            file_    = g("file_path", "filename", "file") or ""
            line_    = int(g("line", "line_number", "lineno") or 0)

            node = TKGNode(
                id=fid, kind=kind, label=str(label)[:120],
                severity=severity, file=str(file_), line=line_, cwe=str(cwe),
            )
            tkg.add_node(node)

            # Add flow edges: source → sink
            if kind == "TAINT_SINK":
                for src_node in tkg.nodes_by_kind("TAINT_SOURCE"):
                    tkg.add_edge(TKGEdge(src=src_node.id, dst=fid, rel="FLOWS_TO"))

        # Try to delegate to existing threat_kg_builder if present
        try:
            from modules.knowledge_graph.src.threat_kg_builder import ThreatKGBuilder
            builder = ThreatKGBuilder()
            external = builder.build(unified_ir) if hasattr(builder, "build") else None
            if external and hasattr(external, "nodes"):
                for nid, node in external.nodes.items():
                    if nid not in tkg.nodes:
                        tkg.nodes[nid] = node
                for edge in getattr(external, "edges", []):
                    tkg.edges.append(edge)
        except Exception:
            pass   # use our in-memory TKG — fully self-contained

        return tkg

    def _infer_kind(self, ftype: str, desc: str) -> str:
        combined = (str(ftype) + " " + str(desc)).lower()
        if any(k in combined for k in ["source", "user_input", "request", "argv"]):
            return "TAINT_SOURCE"
        if any(k in combined for k in ["sink", "sql", "exec", "subprocess", "command", "injection"]):
            return "TAINT_SINK"
        if any(k in combined for k in ["secret", "password", "api_key", "token", "hardcode"]):
            return "SECRET"
        if any(k in combined for k in ["md5", "sha1", "des", "crypto", "cipher", "weak"]):
            return "CRYPTO_ISSUE"
        return "FUNCTION"


# ── Attack path enumerator ───────────────────────────────────────────────────
class PhantomPathFinder:
    """
    Finds exploit chains in the TKG.
    Delegates to existing attack_path_finder if present, otherwise runs own DFS.
    """

    def find(self, tkg: ThreatKG) -> List[AttackPath]:
        paths = []

        # Attempt to use existing attack_path_finder
        try:
            from modules.knowledge_graph.src.attack_path_finder import AttackPathFinder
            finder   = AttackPathFinder()
            raw      = finder.find_paths(tkg) if hasattr(finder, "find_paths") else \
                       finder.enumerate(tkg)   if hasattr(finder, "enumerate")  else []
            for r in raw:
                paths.append(self._wrap(r))
            if paths:
                return paths
        except Exception:
            pass

        # Own DFS: source → sink chains
        sources = tkg.nodes_by_kind("TAINT_SOURCE")
        sinks   = tkg.nodes_by_kind("TAINT_SINK")
        secrets = tkg.nodes_by_kind("SECRET")
        crypto  = tkg.nodes_by_kind("CRYPTO_ISSUE")

        for sink in sinks:
            chain = self._dfs(tkg, sink.id, max_depth=6)
            if chain:
                score = self._score(sink, chain, tkg)
                paths.append(AttackPath(
                    title       = f"Taint flow → {sink.label[:50]}",
                    risk_score  = score,
                    nodes       = [tkg.nodes[n].label[:60] for n in chain if n in tkg.nodes],
                    cwes        = list({tkg.nodes[n].cwe for n in chain if n in tkg.nodes and tkg.nodes[n].cwe}),
                    explanation = f"Attacker-controlled data reaches {sink.kind}: {sink.label[:80]}",
                    remediation = self._remediation(sink),
                    confidence  = "HIGH" if sink.severity in ("CRITICAL","HIGH") else "MEDIUM",
                    tactics     = self._tactics(sink),
                ))

        # Secrets paths
        for s in secrets:
            paths.append(AttackPath(
                title       = f"Credential exposure: {s.label[:50]}",
                risk_score  = 8.5,
                nodes       = [s.label],
                cwes        = [s.cwe or "CWE-798"],
                explanation = "Hard-coded credential found — can be extracted from source or binary.",
                remediation = "Move secret to environment variable or secrets manager (e.g. Vault, AWS Secrets Manager).",
                confidence  = "HIGH",
                tactics     = ["TA0006 — Credential Access"],
            ))

        # Crypto paths
        for c in crypto:
            paths.append(AttackPath(
                title       = f"Weak crypto: {c.label[:50]}",
                risk_score  = 6.0,
                nodes       = [c.label],
                cwes        = [c.cwe or "CWE-327"],
                explanation = "Weak or broken cryptographic algorithm detected.",
                remediation = "Replace with SHA-256/SHA-3 for hashing, AES-256-GCM for encryption.",
                confidence  = "MEDIUM",
                tactics     = ["TA0043 — Reconnaissance", "TA0009 — Collection"],
            ))

        # Sort by risk score descending
        paths.sort(key=lambda p: p.risk_score, reverse=True)
        return paths

    def _dfs(self, tkg: ThreatKG, start: str, max_depth: int) -> List[str]:
        """Walk predecessors to find source→sink chain."""
        visited, stack, path = set(), [(start, [start])], []
        while stack:
            node, cur_path = stack.pop()
            if node in visited or len(cur_path) > max_depth:
                continue
            visited.add(node)
            preds = tkg.predecessors(node)
            if not preds and len(cur_path) > 1:
                path = cur_path
                break
            for p in preds:
                stack.append((p, cur_path + [p]))
        return path

    def _score(self, sink: TKGNode, chain: List[str], tkg: ThreatKG) -> float:
        base   = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 3.0, "INFO": 1.5}.get(sink.severity, 5.0)
        depth  = min(len(chain) * 0.3, 1.5)
        return round(min(base + depth, 10.0), 1)

    def _remediation(self, sink: TKGNode) -> str:
        label = sink.label.lower()
        if "sql" in label:      return "Use parameterised queries or an ORM. Never concatenate user input into SQL."
        if "command" in label or "exec" in label: return "Avoid shell=True. Use subprocess with a list of arguments and strict input validation."
        if "template" in label: return "Use auto-escaping template engines. Never pass raw user input to render()."
        if "pickle" in label:   return "Replace pickle with json or msgpack. Never deserialise untrusted data."
        return "Validate and sanitise all user-controlled input before using in sensitive operations."

    def _tactics(self, sink: TKGNode) -> List[str]:
        label = sink.label.lower()
        tactics = ["TA0001 — Initial Access"]
        if "sql" in label:    tactics.append("TA0007 — Discovery")
        if "exec" in label:   tactics.append("TA0002 — Execution")
        if "template" in label: tactics.append("TA0040 — Impact")
        return tactics

    def _wrap(self, raw) -> AttackPath:
        """Wrap an external AttackPathFinder result into our AttackPath model."""
        if isinstance(raw, AttackPath):
            return raw
        if isinstance(raw, dict):
            return AttackPath(
                title      = raw.get("title", raw.get("name", "Attack path")),
                risk_score = float(raw.get("risk_score", raw.get("score", 5.0))),
                nodes      = raw.get("nodes", raw.get("steps", [])),
                cwes       = raw.get("cwes", []),
                explanation= raw.get("explanation", ""),
                remediation= raw.get("remediation", ""),
            )
        return AttackPath(title=str(raw), risk_score=5.0)


# ── Reasoner — delegates to modules/reasoning if present ────────────────────
class PhantomReasoner:
    def reason(self, paths: List[AttackPath], tkg: ThreatKG) -> List[AttackPath]:
        try:
            from modules.reasoning.src.attack_path_reasoning import AttackPathReasoner
            reasoner = AttackPathReasoner()
            if hasattr(reasoner, "score_paths"):
                return reasoner.score_paths(paths)
            if hasattr(reasoner, "reason"):
                return reasoner.reason(paths)
        except Exception:
            pass
        return paths   # already scored internally

    def explain(self, paths: List[AttackPath]) -> List[AttackPath]:
        try:
            from modules.reasoning.src.explainability_chains import ExplainabilityChain
            explainer = ExplainabilityChain()
            for p in paths:
                if hasattr(explainer, "explain"):
                    p.explanation = explainer.explain(p) or p.explanation
        except Exception:
            pass
        return paths

    def discover(self, tkg: ThreatKG) -> List[AttackPath]:
        """Ask vulnerability_discovery for emergent findings."""
        extra = []
        try:
            from modules.reasoning.src.vulnerability_discovery import VulnerabilityDiscovery
            vd = VulnerabilityDiscovery()
            raw = vd.discover(tkg) if hasattr(vd, "discover") else []
            for r in raw:
                extra.append(PhantomPathFinder()._wrap(r))
        except Exception:
            pass
        return extra


# ── PHANTOM Engine (public API) ──────────────────────────────────────────────
class PhantomEngine:
    """
    Public entry point.
    Usage:
        ph = PhantomEngine()
        paths = ph.run(unified_ir)
    """

    def __init__(self):
        self.builder  = PhantomTKGBuilder()
        self.finder   = PhantomPathFinder()
        self.reasoner = PhantomReasoner()

    def run(self, unified_ir) -> List[AttackPath]:
        # 1. Build TKG
        tkg   = self.builder.build(unified_ir)

        # 2. Find paths
        paths = self.finder.find(tkg)

        # 3. Add emergent discoveries
        extra = self.reasoner.discover(tkg)
        paths = paths + extra

        # 4. Apply reasoning scores
        paths = self.reasoner.reason(paths, tkg)

        # 5. Apply explainability
        paths = self.reasoner.explain(paths)

        # Sort final output
        paths.sort(key=lambda p: p.risk_score, reverse=True)
        return paths

    def run_and_report(self, unified_ir, json_out: str = None) -> List[AttackPath]:
        paths = self.run(unified_ir)
        self._print(paths)
        if json_out:
            with open(json_out, "w") as fh:
                json.dump([p.__dict__ for p in paths], fh, indent=2, default=str)
            print(f"\n  Attack paths saved → {json_out}")
        return paths

    def _print(self, paths: List[AttackPath]):
        print()
        print("─" * 72)
        print("  PHANTOM — RANKED ATTACK PATHS")
        print("─" * 72)
        if not paths:
            print("  No attack paths found.")
            return
        for i, p in enumerate(paths[:10], 1):
            conf_icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(p.confidence, "⚪")
            print(f"\n  [{i:02d}] {conf_icon} Risk {p.score:<5}  {p.title}")
            print(f"       CWEs: {', '.join(p.cwes) if p.cwes else 'N/A'}")
            print(f"       Tactics: {', '.join(p.tactics[:2]) if p.tactics else 'N/A'}")
            if p.nodes:
                print(f"       Chain:")
                for s in p.nodes[:5]:
                    print(f"         → {str(s)[:70]}")
            print(f"       Fix: {p.remediation[:90]}")
        print()
        print(f"  Total attack paths: {len(paths)}")
        print("─" * 72)


# ── CLI (standalone use) ──────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        ir_file = sys.argv[1]
        with open(ir_file) as fh:
            data = json.load(fh)
        ph = PhantomEngine()
        out = sys.argv[2] if len(sys.argv) > 2 else None
        ph.run_and_report(data, json_out=out)
    else:
        # Self-test
        print("PHANTOM self-test...")
        mock_ir = {
            "findings": [
                {"finding_type": "TAINT_SOURCE", "severity": "HIGH",     "description": "User input via request.args",   "file_path": "views.py", "line": 12, "cwe": "CWE-20"},
                {"finding_type": "TAINT_SINK",   "severity": "CRITICAL", "description": "SQL injection sink detected",   "file_path": "views.py", "line": 24, "cwe": "CWE-89"},
                {"finding_type": "SECRET",       "severity": "CRITICAL", "description": "Hardcoded API key found",       "file_path": "config.py","line":  5, "cwe": "CWE-798"},
                {"finding_type": "CRYPTO_ISSUE", "severity": "HIGH",     "description": "MD5 used for password hashing", "file_path": "auth.py",  "line": 31, "cwe": "CWE-327"},
                {"finding_type": "TAINT_SINK",   "severity": "CRITICAL", "description": "Command injection via subprocess shell=True", "file_path": "utils.py", "line": 8, "cwe": "CWE-78"},
            ]
        }
        ph = PhantomEngine()
        paths = ph.run(mock_ir)
        ph._print(paths)
        assert len(paths) >= 3, f"Expected >=3 paths, got {len(paths)}"
        print(f"\n  ✓ PHANTOM self-test passed — {len(paths)} attack paths")
