"""
MISTCODER — PHANTOM BRIDGE
phantom_bridge.py

The missing spine of MISTCODER.

Reads sandbox/unified_ir.json → fixes stringified findings →
converts to TKG schema → runs ThreatKGBuilder → AttackPathFinder
→ ReasoningEngine → ExplainabilityChains → legendary report.

Usage:
    python phantom_bridge.py
    python phantom_bridge.py sandbox/unified_ir.json
    python phantom_bridge.py sandbox/unified_ir.json --json out.json

Zero external dependencies. Python 3.8+
"""
from __future__ import annotations

import ast
import importlib.util
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Root detection ───────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
for sub in [
    "modules/knowledge_graph/src",
    "modules/reasoning/src",
    "modules/oversight/src",
    "modules/ingestion/src",
]:
    sys.path.insert(0, str(ROOT / sub))

# ── Colours ──────────────────────────────────────────────────────────────────
NC = not sys.stdout.isatty()
def _c(code, t): return t if NC else f"\033[{code}m{t}\033[0m"
R  = lambda t: _c("91", t);  Y  = lambda t: _c("93", t)
G  = lambda t: _c("92", t);  C  = lambda t: _c("96", t)
B  = lambda t: _c("94", t);  M  = lambda t: _c("95", t)
BO = lambda t: _c("1",  t);  DI = lambda t: _c("2",  t)
W  = lambda t: _c("97", t)

def sev(s):
    return {
        "CRITICAL": lambda t: R(BO(t)),
        "HIGH":     lambda t: R(t),
        "MEDIUM":   lambda t: Y(t),
        "LOW":      lambda t: G(t),
    }.get(s, DI)(f"[{s}]")

def div(c="─", w=72): return DI(c * w)
def sec(t): return f"\n{div()}\n  {BO(C(t))}\n{div()}"
def hdr(t): return f"\n{div('═')}\n  {BO(W(t))}\n{div('═')}"

BANNER = C(BO(r"""
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝"""))

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Load and FIX unified_ir.json
# The findings are stored as str(dict) — fix with ast.literal_eval
# ─────────────────────────────────────────────────────────────────────────────

def load_and_fix(path: str) -> tuple[list[dict], dict]:
    """
    Load unified_ir.json. Handles both proper JSON objects and
    the stringified-dict format ('{"key": "val"}' stored as a JSON string).
    Returns (findings_list, metadata_dict).
    """
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    raw_findings = raw.get("findings", [])
    fixed: list[dict] = []

    for item in raw_findings:
        if isinstance(item, dict):
            fixed.append(item)
        elif isinstance(item, str):
            try:
                # Try JSON first
                fixed.append(json.loads(item))
            except json.JSONDecodeError:
                try:
                    # Fall back to Python dict literal
                    fixed.append(ast.literal_eval(item))
                except Exception:
                    pass  # skip unparseable

    meta = {k: v for k, v in raw.items() if k != "findings"}
    return fixed, meta


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Convert ORACLE findings → ThreatKGBuilder schema
# ─────────────────────────────────────────────────────────────────────────────

_SEV_CVSS = {"CRITICAL": 9.5, "HIGH": 7.8, "MEDIUM": 5.5, "LOW": 2.5, "INFO": 1.0}

def oracle_to_tkg(findings: list[dict]) -> list[dict]:
    """
    Convert ORACLE flat finding dicts to the schema ThreatKGBuilder.ingest_findings() expects:
    {id, call_name, severity, cvss_score, cwe_id, file, line, taint_path, category, title, detail}
    """
    out = []
    for i, f in enumerate(findings, 1):
        loc   = f.get("location", "unknown:0")
        parts = loc.rsplit(":", 1)
        file  = parts[0] if len(parts) == 2 else loc
        line  = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else 0

        title = f.get("title", "")
        # Extract call name from title (e.g. "http_param → eval_exec" → "eval_exec")
        call_name = title.split("→")[-1].strip() if "→" in title else title

        out.append({
            "id":         f"FD{i:04d}",
            "call_name":  call_name,
            "severity":   f.get("severity", "MEDIUM"),
            "cvss_score": _SEV_CVSS.get(f.get("severity", "MEDIUM"), 5.5),
            "cwe_id":     f.get("cwe", "CWE-20"),
            "file":       file,
            "line":       line,
            "taint_path": title.replace("→", "->").split("->") if "→" in title else [title],
            # extras for rich reporting
            "category":   f.get("category", ""),
            "title":      title,
            "detail":     f.get("detail", ""),
            "confidence": f.get("confidence", 0.8),
            "sanitized":  f.get("sanitized", False),
        })
    return out


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Load modules dynamically (graceful on missing)
# ─────────────────────────────────────────────────────────────────────────────

def _load(rel_path: str, class_name: str):
    """Load a class from a module file, return (class_or_None, error_or_None)."""
    full = ROOT / rel_path
    if not full.exists():
        return None, f"not found: {rel_path}"
    try:
        spec = importlib.util.spec_from_file_location(full.stem, full)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        cls  = getattr(mod, class_name, None)
        if cls is None:
            return None, f"{class_name} not in {rel_path}"
        return cls, None
    except Exception as e:
        return None, str(e)


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — In-memory graph backend (no Neo4j needed)
# ─────────────────────────────────────────────────────────────────────────────

class MemoryBackend:
    """
    Drop-in replacement for the Neo4j backend.
    Stores nodes and edges in memory so the full pipeline runs
    without any database dependency.
    """
    def __init__(self):
        self.nodes: list[dict] = []
        self.edges: list[dict] = []
        self._node_index: dict[str, dict] = {}

    def add_node(self, *args, **kwargs) -> dict:
        # Accept any call signature: (label, props), (id, label, props), (id, label, props, extra)
        props = next((a for a in args if isinstance(a, dict)), {})
        props.update({k: v for k, v in kwargs.items() if k not in ("label",)})
        label = next((a for a in args if isinstance(a, str) and a != props.get("id")), "Node")
        node  = {"_label": label, **props}
        self.nodes.append(node)
        nid   = props.get("id") or props.get("node_id") or str(len(self.nodes))
        self._node_index[nid] = node
        return node

    def create_edge(self, src_id: str, dst_id: str, rel_type: str,
                    properties: dict | None = None) -> dict:
        edge = {"src": src_id, "dst": dst_id, "type": rel_type,
                "props": properties or {}}
        self.edges.append(edge)
        return edge

    def query(self, cypher: str, params: dict | None = None) -> list:
        return []  # no-op for in-memory

    def get_node(self, node_id: str) -> dict | None:
        return self._node_index.get(node_id)

    def get_nodes_by_label(self, label: str) -> list[dict]:
        return [n for n in self.nodes if n.get("_label") == label]

    def close(self): pass
    def clear(self): self.nodes.clear(); self.edges.clear(); self._node_index.clear()


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — Run the full pipeline
# ─────────────────────────────────────────────────────────────────────────────

def run_pipeline(findings_tkg: list[dict], backend: MemoryBackend) -> dict:
    """
    Run ThreatKGBuilder → AttackPathFinder → ReasoningEngine.
    Returns a results dict regardless of which modules are available.
    """
    results = {
        "tkg_nodes":    0,
        "tkg_edges":    0,
        "attack_paths": [],
        "reasoning":    [],
        "modules_ran":  [],
        "errors":       [],
    }

    # ── ThreatKGBuilder ───────────────────────────────────────────────
    ThreatKGBuilder, err = _load(
        "modules/knowledge_graph/src/threat_kg_builder.py", "ThreatKGBuilder")

    if ThreatKGBuilder:
        try:
            builder = ThreatKGBuilder(backend)
            builder.ingest_findings(findings_tkg)
            results["tkg_nodes"]   = len(backend.nodes)
            results["tkg_edges"]   = len(backend.edges)
            results["modules_ran"].append("ThreatKGBuilder")
        except Exception as e:
            results["errors"].append(f"ThreatKGBuilder: {e}")
    else:
        results["errors"].append(f"ThreatKGBuilder: {err}")
        # Build minimal graph ourselves
        for f in findings_tkg:
            backend.create_node("WeaknessNode", {
                "id":       f["id"],
                "severity": f["severity"],
                "cwe":      f["cwe_id"],
                "title":    f["title"],
                "file":     f["file"],
                "line":     f["line"],
                "cvss":     f["cvss_score"],
            })
        results["tkg_nodes"]   = len(backend.nodes)
        results["modules_ran"].append("MemoryGraph(fallback)")

    # ── AttackPathFinder ──────────────────────────────────────────────
    AttackPathFinder, err = _load(
        "modules/knowledge_graph/src/attack_path_finder.py", "AttackPathFinder")

    if AttackPathFinder:
        try:
            finder = AttackPathFinder(backend)
            paths  = finder.find_paths() if hasattr(finder, "find_paths") else \
                     finder.find_attack_paths() if hasattr(finder, "find_attack_paths") else []
            results["attack_paths"] = paths or []
            results["modules_ran"].append("AttackPathFinder")
        except Exception as e:
            results["errors"].append(f"AttackPathFinder: {e}")
            results["attack_paths"] = _infer_attack_paths(findings_tkg)
    else:
        results["errors"].append(f"AttackPathFinder: {err}")
        results["attack_paths"] = _infer_attack_paths(findings_tkg)

    # ── ReasoningEngine ───────────────────────────────────────────────
    ReasoningEngine, err = _load(
        "modules/reasoning/src/attack_path_reasoning.py", "AttackPathReasoner")

    if ReasoningEngine is None:
        ReasoningEngine, err = _load(
            "modules/reasoning/src/attack_path_reasoning.py", "AttackPathReasoning")

    if ReasoningEngine:
        try:
            reasoner = ReasoningEngine()
            r_method = (getattr(reasoner, "reason", None) or
                        getattr(reasoner, "analyse", None) or
                        getattr(reasoner, "analyze", None))
            if r_method:
                reasoning = r_method(results["attack_paths"])
                results["reasoning"]    = reasoning or []
                results["modules_ran"].append("ReasoningEngine")
        except Exception as e:
            results["errors"].append(f"ReasoningEngine: {e}")

    return results


def _infer_attack_paths(findings: list[dict]) -> list[dict]:
    """
    Fallback: infer multi-step attack chains from finding graph.
    Groups findings by file and chains CRITICAL → HIGH sequences.
    """
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        by_file.setdefault(f["file"], []).append(f)

    paths = []
    _SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    for filepath, file_findings in by_file.items():
        sorted_f = sorted(file_findings,
                          key=lambda x: (_SEV_RANK.get(x["severity"], 4), x["line"]))
        crits = [f for f in sorted_f if f["severity"] in ("CRITICAL", "HIGH")]
        if len(crits) >= 2:
            chain_score = sum(f["cvss_score"] for f in crits[:4]) / len(crits[:4])
            paths.append({
                "id":          f"PATH-{len(paths)+1:03d}",
                "file":        filepath,
                "steps":       crits[:4],
                "depth":       len(crits[:4]),
                "score":       round(chain_score, 2),
                "entry_point": crits[0]["title"],
                "impact":      crits[-1]["title"],
                "min_tier":    "T1" if chain_score >= 8.0 else "T2",
            })

    paths.sort(key=lambda p: p["score"], reverse=True)
    return paths[:10]


# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — The legendary report
# ─────────────────────────────────────────────────────────────────────────────

def render(findings_raw: list[dict], findings_tkg: list[dict],
           pipeline: dict, meta: dict, elapsed: int,
           json_out: str = ""):

    print(BANNER)
    print(DI("  PHANTOM BRIDGE — Full Intelligence Pipeline  │  TKG + Attack Paths + Reasoning\n"))

    scan_id = meta.get("scan_id", "UNKNOWN")
    ts      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    target  = meta.get("target", "modules/")

    print(hdr("PHANTOM INTELLIGENCE REPORT"))
    print(f"  {DI('Scan ID  :')} {C(scan_id)}")
    print(f"  {DI('Target   :')} {C(target)}")
    print(f"  {DI('Timestamp:')} {ts}")
    print(f"  {DI('Duration :')} {elapsed}ms")
    print(f"  {DI('Modules  :')} {', '.join(pipeline['modules_ran']) or 'fallback'}")

    # ── Severity histogram ────────────────────────────────────────────
    counts = {}
    for f in findings_raw:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1

    print(sec("FINDINGS DISTRIBUTION"))
    print(f"  {DI('Total:')} {BO(str(len(findings_raw)))}  across "
          f"{len({f['file'] for f in findings_tkg})} files\n")

    bar_chars = 45
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        c = counts.get(s, 0)
        if not c: continue
        bar = "█" * int(c / max(counts.values()) * bar_chars)
        print(f"  {sev(s):<30}  {str(c):<4}  {DI(bar)}")

    # ── Knowledge graph stats ─────────────────────────────────────────
    print(sec("THREAT KNOWLEDGE GRAPH"))
    print(f"  {DI('Nodes built  :')} {BO(str(pipeline['tkg_nodes']))}  weakness nodes")
    print(f"  {DI('Edges built  :')} {BO(str(pipeline['tkg_edges']))}  relationships")
    print(f"  {DI('Attack paths :')} {BO(str(len(pipeline['attack_paths'])))}  chains enumerated")

    if pipeline["errors"]:
        for e in pipeline["errors"]:
            print(f"  {DI('⚠')} {DI(e)}")

    # ── Top attack paths ──────────────────────────────────────────────
    paths = pipeline["attack_paths"]
    if paths:
        print(sec(f"RANKED ATTACK CHAINS  (top {min(5, len(paths))})"))

        for i, path in enumerate(paths[:5], 1):
            score = path.get("score", 0)
            depth = path.get("depth", 0)
            tier  = path.get("min_tier", "T2")
            fpath = os.path.basename(str(path.get("file", "")))
            entry = path.get("entry_point", "?")
            impact= path.get("impact", "?")

            score_color = R if score >= 8.0 else Y if score >= 5.0 else G
            print(f"\n  {BO(score_color(f'#{i}'))}  "
                  f"Score: {score_color(str(score))}  "
                  f"Depth: {depth} steps  "
                  f"Min adversary: {BO(tier)}")
            print(f"     {DI('File  :')} {C(fpath)}")
            print(f"     {DI('Entry :')} {entry}")
            print(f"     {DI('Impact:')} {impact}")

            steps = path.get("steps", [])
            if steps:
                print(f"     {DI('Chain :')}", end="")
                chain = " → ".join(s.get("title", "?")[:35] for s in steps[:4])
                print(f" {DI(chain)}")

    # ── Critical findings detail ──────────────────────────────────────
    crits = [f for f in findings_raw if f.get("severity") in ("CRITICAL", "HIGH")]
    crits.sort(key=lambda f: (
        ["CRITICAL","HIGH"].index(f.get("severity","HIGH")),
        -f.get("confidence", 0),
    ))

    if crits:
        print(sec(f"CRITICAL & HIGH FINDINGS  ({len(crits)} total — top 8 shown)"))

        seen: set = set()
        shown = 0
        for f in crits:
            key = (f.get("title"), f.get("file"))
            if key in seen or shown >= 8:
                continue
            seen.add(key); shown += 1

            loc = str(f.get("location", f.get("file", "?")))
            fname = os.path.basename(loc.split(":")[0]) + \
                    (":" + loc.split(":")[1] if ":" in loc else "")
            cwe  = DI(f.get("cwe", ""))
            conf = f.get("confidence", 0)
            conf_str = G("high") if conf >= 0.8 else Y("medium") if conf >= 0.5 else DI("low")

            print(f"\n  {sev(f['severity'])}  {BO(f.get('title', '?'))}")
            print(f"    {DI('File  :')} {C(fname)}  {cwe}  confidence: {conf_str}")
            print(f"    {DI('Detail:')} {f.get('detail', '')[:80]}")

    # ── Files most at risk ────────────────────────────────────────────
    file_risk: dict[str, dict] = {}
    for f in findings_raw:
        fp = f.get("file", "unknown")
        fname = os.path.basename(fp)
        if fname not in file_risk:
            file_risk[fname] = {"critical": 0, "high": 0, "total": 0, "path": fp}
        s = f.get("severity", "")
        if s == "CRITICAL": file_risk[fname]["critical"] += 1
        if s == "HIGH":     file_risk[fname]["high"]     += 1
        file_risk[fname]["total"] += 1

    ranked = sorted(file_risk.items(),
                    key=lambda x: (x[1]["critical"], x[1]["high"]), reverse=True)

    print(sec("FILES MOST AT RISK"))
    print(f"  {'FILE':<45} {'CRIT':>5} {'HIGH':>5} {'TOTAL':>6}")
    print(f"  {DI('─'*63)}")
    for fname, counts in ranked[:10]:
        c_str = R(str(counts["critical"])) if counts["critical"] else DI("0")
        h_str = Y(str(counts["high"]))     if counts["high"]     else DI("0")
        print(f"  {C(fname):<53}  {c_str:>5}  {h_str:>5}  {DI(str(counts['total'])):>6}")

    # ── Risk verdict ──────────────────────────────────────────────────
    print(sec("RISK VERDICT"))
    n_crit = counts.get("CRITICAL", 0) if isinstance(counts, dict) else sum(1 for f in findings_raw if f.get("severity") == "CRITICAL")
    n_high = counts.get("HIGH", 0)     if isinstance(counts, dict) else sum(1 for f in findings_raw if f.get("severity") == "HIGH")

    if n_crit >= 3:
        print(f"\n  {R(BO('■ CRITICAL RISK'))}  {n_crit} critical vulnerabilities")
        print(f"  {R('Stop all deployment. Attack chains confirmed.')}")
    elif n_crit >= 1:
        print(f"\n  {R(BO('■ HIGH RISK'))}  {n_crit} critical, {n_high} high")
        print(f"  {Y('Remediate CRITICAL findings before any production release.')}")
    elif n_high >= 5:
        print(f"\n  {Y(BO('■ ELEVATED RISK'))}  {n_high} high-severity findings")
        print(f"  {Y('Schedule remediation sprint.')}")
    else:
        print(f"\n  {G(BO('■ MODERATE RISK'))}  Review findings in next sprint.")

    # ── Export ────────────────────────────────────────────────────────
    if json_out:
        export = {
            "phantom_version": "1.0.0",
            "scan_id":    scan_id,
            "timestamp":  ts,
            "summary":    counts,
            "tkg": {
                "nodes": pipeline["tkg_nodes"],
                "edges": pipeline["tkg_edges"],
            },
            "attack_paths":  pipeline["attack_paths"],
            "findings":      findings_raw,
            "modules_ran":   pipeline["modules_ran"],
        }
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump(export, fh, indent=2, default=str)
        print(f"\n  {G('✓')} Phantom report → {C(json_out)}")

    print(f"\n{div('═')}")
    print(f"  {DI('PHANTOM BRIDGE complete')}  {DI('│')}  "
          f"findings: {BO(str(len(findings_raw)))}  "
          f"paths: {BO(str(len(paths)))}  "
          f"time: {elapsed}ms\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ir_path  = sys.argv[1] if len(sys.argv) > 1 else "sandbox/unified_ir.json"
    json_out = ""
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--json" and i + 1 < len(sys.argv):
            json_out = sys.argv[i + 1]

    if not Path(ir_path).exists():
        print(R(f"Error: {ir_path} not found"))
        print(DI("Run: python mistcoder.py scan modules/ --json sandbox/unified_ir.json"))
        sys.exit(1)

    t0 = time.perf_counter()

    findings_raw, meta = load_and_fix(ir_path)
    findings_tkg = oracle_to_tkg(findings_raw)

    backend  = MemoryBackend()
    pipeline = run_pipeline(findings_tkg, backend)

    elapsed = int((time.perf_counter() - t0) * 1000)

    render(findings_raw, findings_tkg, pipeline, meta, elapsed,
           json_out=json_out or ir_path.replace("unified_ir.json", "phantom_report.json"))


if __name__ == "__main__":
    main()
