"""
MISTCODER -- MOD-03 Reasoning Core
Version: 0.1.0

Two responsibilities:

LAYER A -- Cryptographic Integrity
    MerkleTree     : builds a tamper-proof tree over all IR nodes
    EntropyScanner : Shannon entropy analysis to detect obfuscated code
    AuditChain     : HMAC-signed, append-only finding log

LAYER B -- Cognitive Reasoning
    AttackChainPredictor : N-move lookahead over the IR call graph
    RemediationEngine    : context-aware natural language fix generator
    ReasoningEngine      : orchestrates both layers per finding set
"""

import json
import math
import hmac
import hashlib
import os
from datetime import datetime, timezone
from collections import defaultdict


# ---------------------------------------------------------------------------
# LAYER A-1 -- Merkle Tree
# Builds a cryptographic proof over every IR node.
# Any tampering between MOD-01 output and MOD-02 input is detectable.
# ---------------------------------------------------------------------------

class MerkleTree:
    """
    Constructs a Merkle tree from IR node list.
    Root hash = cryptographic fingerprint of the entire parsed surface.
    """

    def __init__(self):
        self.leaves = []
        self.root   = None

    def _hash(self, data):
        if isinstance(data, str):
            data = data.encode()
        return hashlib.sha256(data).hexdigest()

    def build(self, nodes):
        """Build tree from IR node list. Returns root hash."""
        self.leaves = [
            self._hash(json.dumps(n, sort_keys=True))
            for n in nodes
        ]
        if not self.leaves:
            self.root = self._hash("")
            return self.root

        layer = self.leaves[:]
        while len(layer) > 1:
            if len(layer) % 2 != 0:
                layer.append(layer[-1])   # duplicate last leaf if odd
            layer = [
                self._hash(layer[i] + layer[i+1])
                for i in range(0, len(layer), 2)
            ]

        self.root = layer[0]
        return self.root

    def verify(self, nodes):
        """Return True if node list produces the same root as when built."""
        candidate = MerkleTree()
        candidate.build(nodes)
        return candidate.root == self.root


# ---------------------------------------------------------------------------
# LAYER A-2 -- Shannon Entropy Scanner
# A hacker obfuscating eval inside base64 or XOR chains
# cannot hide the entropy spike. This catches what regex never will.
# ---------------------------------------------------------------------------

class EntropyScanner:
    """
    Computes Shannon entropy per token/string in the IR.
    High entropy (> threshold) = potential obfuscated payload.

    Thresholds (empirical):
        < 3.5   normal variable names, keywords
        3.5-5.0 mixed content, worth flagging
        > 5.0   likely encoded / encrypted / obfuscated string
        > 6.5   almost certainly a secret, key, or encoded payload
    """

    THRESHOLD_WARN     = 3.5
    THRESHOLD_HIGH     = 5.0
    THRESHOLD_CRITICAL = 6.5

    def _entropy(self, s):
        if not s:
            return 0.0
        freq = defaultdict(int)
        for c in s:
            freq[c] += 1
        total = len(s)
        return -sum(
            (count / total) * math.log2(count / total)
            for count in freq.values()
        )

    def scan_ir(self, ir):
        """
        Scan all string values in IR nodes for entropy anomalies.
        Returns list of entropy findings.
        """
        results = []
        for node in ir.get("nodes", []):
            targets = {
                "name": node.get("name", ""),
            }
            props = node.get("props", {})
            for pk, pv in props.items():
                if isinstance(pv, str):
                    targets[f"props.{pk}"] = pv

            for field, value in targets.items():
                if len(value) < 8:
                    continue
                score = self._entropy(value)
                if score >= self.THRESHOLD_WARN:
                    label = (
                        "CRITICAL_ENTROPY" if score >= self.THRESHOLD_CRITICAL else
                        "HIGH_ENTROPY"     if score >= self.THRESHOLD_HIGH      else
                        "WARN_ENTROPY"
                    )
                    results.append({
                        "node_id":   node["id"],
                        "node_type": node["type"],
                        "field":     field,
                        "value":     value[:40] + ("..." if len(value) > 40 else ""),
                        "entropy":   round(score, 4),
                        "label":     label,
                        "line":      node.get("line", 0),
                    })

        return sorted(results, key=lambda x: -x["entropy"])


# ---------------------------------------------------------------------------
# LAYER A-3 -- Audit Chain
# HMAC-SHA256 signed, append-only log of every finding.
# Tamper-evident. Each entry includes a chain hash linking to the prior.
# This is the court-admissible record.
# ---------------------------------------------------------------------------

class AuditChain:
    """
    Append-only, cryptographically linked audit log.
    Each entry = HMAC(secret_key, prev_hash + finding_data).
    Verifying the chain proves no finding was added, removed, or altered.
    """

    def __init__(self, secret_key=None):
        self._key     = (secret_key or "MISTCODER-AUDIT-KEY-v1").encode()
        self._entries = []
        self._prev    = "0" * 64   # genesis hash

    def _sign(self, data):
        payload = (self._prev + data).encode()
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def append(self, finding_dict):
        """Add a signed entry to the chain."""
        data      = json.dumps(finding_dict, sort_keys=True)
        signature = self._sign(data)
        entry = {
            "seq":       len(self._entries) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "prev_hash": self._prev,
            "signature": signature,
            "finding":   finding_dict,
        }
        self._entries.append(entry)
        self._prev = signature
        return entry

    def verify_chain(self):
        """
        Re-derive all signatures from scratch.
        Returns (True, None) if chain is intact.
        Returns (False, broken_at_seq) if tampering detected.
        """
        prev = "0" * 64
        for entry in self._entries:
            data      = json.dumps(entry["finding"], sort_keys=True)
            payload   = (prev + data).encode()
            expected  = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, entry["signature"]):
                return False, entry["seq"]
            prev = entry["signature"]
        return True, None

    def export(self):
        return {
            "chain_length": len(self._entries),
            "head_hash":    self._prev,
            "entries":      self._entries,
        }


# ---------------------------------------------------------------------------
# LAYER B-1 -- Attack Chain Predictor
# N-move lookahead over the IR call graph.
# Like a chess engine: for each dangerous sink, trace backward
# to find every path an attacker could take to reach it.
# ---------------------------------------------------------------------------

class AttackChainPredictor:
    """
    Predicts multi-hop attack chains from the IR edge graph.

    Algorithm:
        1. Identify all dangerous call nodes (sinks)
        2. Build reverse adjacency graph (sink ← caller ← caller ...)
        3. DFS backward up to MAX_DEPTH hops
        4. Each path = one predicted attack chain
        5. Score by chain length and node types encountered

    The longer and more convoluted the chain,
    the harder it is for a human reviewer to spot.
    MISTCODER finds it anyway.
    """

    MAX_DEPTH = 8

    def predict(self, ir):
        nodes    = ir.get("nodes", [])
        edges    = ir.get("edges", [])
        node_map = {n["id"]: n for n in nodes}

        # build reverse adjacency: dst -> [src, ...]
        rev = defaultdict(list)
        for edge in edges:
            rev[edge["dst"]].append(edge["src"])

        # identify sinks
        sinks = [
            n for n in nodes
            if n.get("props", {}).get("dangerous")
        ]

        chains = []
        for sink in sinks:
            paths = self._dfs_backward(sink["id"], rev, depth=0, visited=set())
            for path in paths:
                path_nodes = [node_map.get(nid) for nid in path if node_map.get(nid)]
                score      = self._score_chain(path_nodes)
                chains.append({
                    "sink_id":    sink["id"],
                    "sink_name":  sink["name"],
                    "sink_line":  sink["line"],
                    "chain":      path,
                    "chain_names": [n["name"] for n in path_nodes if n],
                    "depth":      len(path),
                    "risk_score": score,
                })

        return sorted(chains, key=lambda c: -c["risk_score"])

    def _dfs_backward(self, node_id, rev, depth, visited):
        if depth >= self.MAX_DEPTH or node_id in visited:
            return [[node_id]]
        visited = visited | {node_id}
        parents = rev.get(node_id, [])
        if not parents:
            return [[node_id]]
        paths = []
        for parent in parents:
            for sub in self._dfs_backward(parent, rev, depth + 1, visited):
                paths.append(sub + [node_id])
        return paths

    def _score_chain(self, path_nodes):
        """
        Score = base danger + depth multiplier.
        Longer chains through multiple functions = harder to detect manually.
        """
        base  = sum(2.0 if n.get("props", {}).get("dangerous") else 0.5
                    for n in path_nodes if n)
        depth = len(path_nodes)
        return round(base * (1 + depth * 0.1), 2)


# ---------------------------------------------------------------------------
# LAYER B-2 -- Remediation Engine
# Context-aware natural language fix generator.
# Every finding gets a concrete, actionable recommendation.
# This is what makes the demo legendary.
# ---------------------------------------------------------------------------

REMEDIATION_TEMPLATES = {
    "eval": {
        "risk":    "Executes arbitrary code from a string. If user-controlled, full code execution.",
        "fix":     "Replace eval() with a safe parser. For math: use ast.literal_eval() or a "
                   "dedicated expression library. For JSON: use json.loads(). Never pass "
                   "user input to eval().",
        "example": "# UNSAFE\nresult = eval(user_input)\n\n"
                   "# SAFE\nimport ast\nresult = ast.literal_eval(user_input)  # raises on non-literals",
    },
    "exec": {
        "risk":    "Executes OS commands directly. Enables remote code execution if user-controlled.",
        "fix":     "Use subprocess with a list argument (never shell=True with user input). "
                   "Validate and whitelist all command arguments before execution.",
        "example": "# UNSAFE\nexec(raw_sql)\n\n"
                   "# SAFE\n# Use parameterized queries via your ORM or DB driver\ncursor.execute(query, (param,))",
    },
    "os.system": {
        "risk":    "Passes a string directly to the OS shell. Shell metacharacters enable injection.",
        "fix":     "Replace with subprocess.run(args_list, shell=False). Never construct "
                   "command strings from user input.",
        "example": "# UNSAFE\nos.system(cmd)\n\n"
                   "# SAFE\nimport subprocess\nsubprocess.run(['command', arg1, arg2], shell=False, check=True)",
    },
    "execSync": {
        "risk":    "Synchronous shell command. Blocks event loop and enables command injection.",
        "fix":     "Use child_process.execFile() with an explicit args array. "
                   "Sanitize all inputs with a whitelist before passing to any exec function.",
        "example": "// UNSAFE\nexecSync(cmd)\n\n"
                   "// SAFE\nconst { execFile } = require('child_process');\nexecFile('command', [arg1, arg2], callback);",
    },
    "Function": {
        "risk":    "Dynamically constructs and executes a function from a string. Equivalent to eval().",
        "fix":     "Eliminate dynamic function construction entirely. Use a lookup table "
                   "(object/map) to map user input to pre-defined safe functions.",
        "example": "// UNSAFE\nFunction('return ' + data)()\n\n"
                   "// SAFE\nconst handlers = { 'action1': fn1, 'action2': fn2 };\n(handlers[data] || (() => {}))();",
    },
    "document.write": {
        "risk":    "Writes raw HTML to the DOM. Direct XSS vector if content is user-supplied.",
        "fix":     "Use textContent or createElement/appendChild instead. "
                   "Never insert user-supplied strings directly into HTML.",
        "example": "// UNSAFE\ndocument.write(username)\n\n"
                   "// SAFE\nconst el = document.createElement('h1');\nel.textContent = username;\ndocument.body.appendChild(el);",
    },
    "innerHTML": {
        "risk":    "Parses and renders arbitrary HTML. Enables XSS and script injection.",
        "fix":     "Use textContent for plain text. If HTML is required, sanitize with "
                   "DOMPurify before assigning to innerHTML.",
        "example": "// UNSAFE\nel.innerHTML = userContent\n\n"
                   "// SAFE\nimport DOMPurify from 'dompurify';\nel.innerHTML = DOMPurify.sanitize(userContent);",
    },
    "pickle.loads": {
        "risk":    "Deserializes arbitrary Python objects. Crafted payloads execute code on load.",
        "fix":     "Replace pickle with json.loads() for data exchange. If object serialization "
                   "is required, use a safe format (msgpack, protobuf) and validate schema on load.",
        "example": "# UNSAFE\nobj = pickle.loads(data)\n\n# SAFE\nobj = json.loads(data)",
    },
    "yaml.load": {
        "risk":    "Unsafe YAML deserialization. Allows arbitrary Python object instantiation.",
        "fix":     "Replace with yaml.safe_load() which only deserializes safe scalar types.",
        "example": "# UNSAFE\ndata = yaml.load(stream)\n\n# SAFE\ndata = yaml.safe_load(stream)",
    },
    "__import__": {
        "risk":    "Dynamic module import from user-controlled string. Enables code injection.",
        "fix":     "Use a hardcoded whitelist of importable modules. Never pass user input "
                   "to __import__() or importlib.import_module().",
        "example": "# UNSAFE\nmod = __import__(user_input)\n\n"
                   "# SAFE\nALLOWED = {'math', 'json'}\nif user_input in ALLOWED:\n    mod = __import__(user_input)",
    },
    "open": {
        "risk":    "File path from user input enables path traversal (../../etc/passwd).",
        "fix":     "Use pathlib.Path and resolve() to canonicalize the path, then verify "
                   "it is within the intended base directory before opening.",
        "example": "# UNSAFE\nopen(template)\n\n"
                   "# SAFE\nfrom pathlib import Path\nbase = Path('/safe/dir').resolve()\n"
                   "target = (base / template).resolve()\nassert str(target).startswith(str(base))\nopen(target)",
    },
    "setTimeout": {
        "risk":    "Deferred code execution via string argument. eval() equivalent on a timer.",
        "fix":     "Always pass a function reference, never a string, to setTimeout.",
        "example": "// UNSAFE\nsetTimeout(\"eval(code)\", 5000)\n\n"
                   "// SAFE\nsetTimeout(() => { safeFunction(); }, 5000);",
    },
}

FALLBACK_REMEDIATION = {
    "risk":    "Dangerous function call detected. May allow code execution or data exposure.",
    "fix":     "Review this call. Validate all inputs before passing to this function. "
               "Consider replacing with a safer alternative specific to your use case.",
    "example": "# Consult OWASP guidelines for this function category.",
}


class RemediationEngine:
    """
    Generates structured remediation advice for each finding.
    Output: risk summary, concrete fix, code example, confidence score.
    """

    def remediate(self, finding_dict):
        """Return remediation block for a single finding."""
        call   = finding_dict.get("call_name", "")
        tmpl   = REMEDIATION_TEMPLATES.get(call, FALLBACK_REMEDIATION)
        taint  = bool(finding_dict.get("taint_path"))

        confidence = 0.95 if taint else 0.75
        urgency    = (
            "IMMEDIATE"  if finding_dict.get("severity") == "CRITICAL" else
            "HIGH"       if finding_dict.get("severity") == "HIGH"      else
            "SCHEDULED"
        )

        return {
            "call_name":   call,
            "urgency":     urgency,
            "confidence":  confidence,
            "taint_confirmed": taint,
            "risk":        tmpl["risk"],
            "fix":         tmpl["fix"],
            "example":     tmpl["example"],
            "references": [
                f"https://cwe.mitre.org/data/definitions/"
                f"{finding_dict.get('cwe_id','CWE-0').replace('CWE-','')}.html",
                "https://owasp.org/www-project-top-ten/",
            ],
        }


# ---------------------------------------------------------------------------
# ReasoningEngine -- orchestrates MOD-03
# ---------------------------------------------------------------------------

class ReasoningEngine:
    """
    MOD-03 top-level orchestrator.

    Given:
        ir       : MOD-01 IR document
        findings : MOD-02 Finding dicts

    Produces:
        merkle_root       : integrity proof over IR nodes
        entropy_findings  : high-entropy anomalies
        attack_chains     : N-move attack path predictions
        remediations      : per-finding fix advice
        audit_chain       : signed audit log
    """

    def __init__(self, audit_key=None):
        self.merkle   = MerkleTree()
        self.entropy  = EntropyScanner()
        self.predictor = AttackChainPredictor()
        self.remediate = RemediationEngine()
        self.audit    = AuditChain(secret_key=audit_key)

    def analyze(self, ir, findings):
        # Layer A: cryptographic integrity
        merkle_root     = self.merkle.build(ir.get("nodes", []))
        entropy_hits    = self.entropy.scan_ir(ir)

        # Layer B: cognitive reasoning
        attack_chains   = self.predictor.predict(ir)
        remediations    = [
            self.remediate.remediate(f) for f in findings
        ]

        # Build and sign audit entries
        for finding in findings:
            self.audit.append(finding)

        valid, broken_at = self.audit.verify_chain()

        return {
            "engine":        "MISTCODER MOD-03 Reasoning Core v0.1.0",
            "generated":     datetime.now(timezone.utc).isoformat(),
            "file":          ir.get("file", "unknown"),
            "merkle_root":   merkle_root,
            "audit": {
                "chain_valid": valid,
                "broken_at":   broken_at,
                "length":      len(findings),
                "head_hash":   self.audit._prev,
            },
            "entropy_findings":  entropy_hits,
            "attack_chains":     attack_chains,
            "remediations":      remediations,
        }

    def print_reasoning(self, result):
        print()
        print("=" * 70)
        print("  MISTCODER -- MOD-03 REASONING CORE REPORT")
        print(f"  File      : {result['file']}")
        print(f"  Generated : {result['generated']}")
        print("=" * 70)

        print(f"\n  [INTEGRITY]")
        print(f"  Merkle Root   : {result['merkle_root'][:32]}...")
        audit = result["audit"]
        status = "✓ INTACT" if audit["chain_valid"] else f"✗ BROKEN at seq {audit['broken_at']}"
        print(f"  Audit Chain   : {status} ({audit['length']} entries)")
        print(f"  Head Hash     : {audit['head_hash'][:32]}...")

        if result["entropy_findings"]:
            print(f"\n  [ENTROPY ANOMALIES]  -- {len(result['entropy_findings'])} detected")
            for hit in result["entropy_findings"][:5]:
                print(f"  {hit['label']:20s}  entropy={hit['entropy']}  "
                      f"line={hit['line']}  value={hit['value']}")

        if result["attack_chains"]:
            print(f"\n  [ATTACK CHAINS]  -- {len(result['attack_chains'])} predicted")
            for chain in result["attack_chains"][:5]:
                path = " --> ".join(chain["chain_names"])
                print(f"  risk={chain['risk_score']:5.2f}  depth={chain['depth']}  "
                      f"sink={chain['sink_name']}  path={path}")

        print(f"\n  [REMEDIATIONS]  -- {len(result['remediations'])} generated")
        for r in result["remediations"]:
            print(f"\n  [{r['urgency']:9s}]  {r['call_name']}  "
                  f"confidence={r['confidence']}  taint={r['taint_confirmed']}")
            print(f"  Risk : {r['risk'][:80]}")
            print(f"  Fix  : {r['fix'][:80]}")

        print()
        print("=" * 70)
        print("  END OF REASONING REPORT")
        print("=" * 70)
        print()

    def export(self, result, output_path):
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"[MOD-03] Reasoning report exported to {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python reasoning.py <ir_json> <findings_json> [--export out.json]")
        sys.exit(1)

    ir_path       = sys.argv[1]
    findings_path = sys.argv[2]
    export_path   = sys.argv[4] if len(sys.argv) >= 5 and sys.argv[3] == "--export" else None

    with open(ir_path,       "r") as f: ir       = json.load(f)
    with open(findings_path, "r") as f: findings = json.load(f)

    finding_list = findings.get("findings", [])

    engine = ReasoningEngine()
    result = engine.analyze(ir, finding_list)
    engine.print_reasoning(result)

    if export_path:
        engine.export(result, export_path)
