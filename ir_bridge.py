"""
MISTCODER — NEXUS
modules/ingestion/src/ir_bridge.py

Converts heterogeneous engine outputs into a single, unified
Intelligence Record (IR) that feeds modules/knowledge_graph/.

Every engine speaks a different dialect:
  ORACLE      → FileAnalysisResult objects
  parser.py   → {nodes, edges, metadata} dicts
  url_scanner → {nodes, edges, metadata} dicts (url scan_type)
  binary_lifting → (future) binary IR dicts

This bridge normalises all of them into one schema:
  UnifiedIR → knowledge_graph/src/threat_kg_builder.py
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Unified finding — the common currency between all engines and the TKG
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class UnifiedFinding:
    id:           str
    severity:     str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category:     str          # TAINT_FLOW | CRYPTO | SECRET | HEADER | JS | ENDPOINT
    title:        str
    detail:       str
    location:     str          # "file:line" or "url" or "binary+offset"
    source_engine: str         # "ORACLE" | "PARSER" | "URL_SCANNER" | "BINARY"
    cwe_ids:      list[str]    = field(default_factory=list)
    confidence:   float        = 0.8
    remediation:  str          = ""
    raw:          dict[str, Any] = field(default_factory=dict)

    def to_tkg_node(self) -> dict[str, Any]:
        """Emit a node dict compatible with threat_kg_builder.py WeaknessNode."""
        sev_to_cvss = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0,
                       "LOW": 3.0, "INFO": 1.0}
        return {
            "id":           self.id,
            "kind":         "confirmed_vuln" if self.confidence >= 0.8 else "probable_vuln",
            "label":        self.title,
            "description":  self.detail,
            "severity":     self.severity.lower(),
            "confidence":   "high" if self.confidence >= 0.8 else "medium",
            "cvss_score":   sev_to_cvss.get(self.severity, 5.0),
            "cve_refs":     [],
            "cwe_refs":     self.cwe_ids,
            "location":     self.location,
            "source_engine": self.source_engine,
            "exploitability": min(self.confidence, 0.95),
            "detectability":  0.4 if self.severity == "CRITICAL" else 0.6,
            "reasoning_chain": [self.detail, f"Detected by {self.source_engine}"],
        }


@dataclass
class UnifiedIR:
    """
    The single output of the IR bridge — fed directly into knowledge_graph/.
    """
    target:       str
    scan_id:      str
    timestamp:    str
    engines_used: list[str]
    findings:     list[UnifiedFinding] = field(default_factory=list)
    metadata:     dict[str, Any]       = field(default_factory=dict)

    # ── Stats ────────────────────────────────────────────────────────
    @property
    def critical(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def total(self) -> int:
        return len(self.findings)

    # ── Serialisation ────────────────────────────────────────────────
    def to_tkg_input(self) -> dict[str, Any]:
        """
        Produce the dict that threat_kg_builder.py expects as input.
        Schema mirrors what modules/knowledge_graph/src/threat_kg_builder.py
        reads from sandbox/detection_config.json.
        """
        return {
            "mistcoder_version":  "0.3.0-nexus",
            "scan_id":            self.scan_id,
            "target":             self.target,
            "timestamp":          self.timestamp,
            "engines":            self.engines_used,
            "summary": {
                "total":    self.total,
                "critical": self.critical,
                "high":     self.high,
                "medium":   sum(1 for f in self.findings if f.severity == "MEDIUM"),
                "low":      sum(1 for f in self.findings if f.severity == "LOW"),
            },
            "weakness_nodes": [f.to_tkg_node() for f in self.findings],
            "metadata": self.metadata,
        }

    def export(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_tkg_input(), fh, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Converters — one per engine
# ─────────────────────────────────────────────────────────────────────────────

def _uid(prefix: str, n: int) -> str:
    return f"{prefix}-{n:05d}"


def from_oracle(results: list, scan_id: str, target: str) -> UnifiedIR:
    """
    Convert a list of FileAnalysisResult objects (from python_ast_walker)
    into a UnifiedIR.
    """
    findings: list[UnifiedFinding] = []
    n = 0

    for result in results:
        if result.parse_error or result.finding_count == 0:
            continue

        # Taint flows
        for flow in result.flows:
            n += 1
            findings.append(UnifiedFinding(
                id           = _uid("ORC-TAINT", n),
                severity     = flow.severity,
                category     = "TAINT_FLOW",
                title        = f"{flow.source.kind.value} → {flow.sink.kind.value}",
                detail       = (f"Taint from {flow.source.kind.value} at "
                                f"{flow.source.location} flows to "
                                f"{flow.sink.kind.value} at {flow.sink.location}"),
                location     = str(flow.sink.location),
                source_engine= "ORACLE",
                cwe_ids      = [flow.cwe()],
                confidence   = flow.confidence,
            ))

        # Crypto findings
        for c in result.crypto:
            n += 1
            findings.append(UnifiedFinding(
                id           = _uid("ORC-CRYPTO", n),
                severity     = c.severity,
                category     = "CRYPTO",
                title        = c.kind.value.replace("_", " ").title(),
                detail       = c.detail or c.expression[:80],
                location     = str(c.location),
                source_engine= "ORACLE",
                cwe_ids      = ["CWE-327"],
                confidence   = 0.95,
            ))

        # Secret findings
        for s in result.secrets:
            n += 1
            findings.append(UnifiedFinding(
                id           = _uid("ORC-SECRET", n),
                severity     = s.severity,
                category     = "SECRET",
                title        = s.kind.value.replace("_", " ").title(),
                detail       = f"{s.pattern} detected (entropy {s.entropy:.2f})",
                location     = str(s.location),
                source_engine= "ORACLE",
                cwe_ids      = ["CWE-312", "CWE-798"],
                confidence   = min(0.9, s.entropy / 5.0),
            ))

    ts = datetime.now(timezone.utc).isoformat()
    return UnifiedIR(
        target       = target,
        scan_id      = scan_id,
        timestamp    = ts,
        engines_used = ["ORACLE"],
        findings     = findings,
        metadata     = {"files_scanned": len(results)},
    )


def from_parser(ir_dict: dict[str, Any], scan_id: str) -> UnifiedIR:
    """
    Convert a parser.py IR dict into UnifiedIR.
    Works for both PythonParser and JavaScriptParser output.
    """
    findings: list[UnifiedFinding] = []
    target = ir_dict.get("file", "unknown")
    n = 0

    for node in ir_dict.get("nodes", []):
        props = node.get("props", {})

        if node["type"] == "secret_flag":
            n += 1
            findings.append(UnifiedFinding(
                id           = _uid("PRS-SECRET", n),
                severity     = "HIGH",
                category     = "SECRET",
                title        = f"Potential secret: {node['name']}",
                detail       = f"Variable name '{node['name']}' matches secret keyword pattern",
                location     = f"{target}:{node.get('line', 0)}",
                source_engine= "PARSER",
                cwe_ids      = ["CWE-312"],
                confidence   = 0.65,
            ))

        elif node["type"] == "call" and props.get("dangerous"):
            n += 1
            findings.append(UnifiedFinding(
                id           = _uid("PRS-DANGEROUS", n),
                severity     = "HIGH",
                category     = "DANGEROUS_CALL",
                title        = f"Dangerous call: {node['name']}()",
                detail       = f"Security-sensitive function '{node['name']}' called",
                location     = f"{target}:{node.get('line', 0)}",
                source_engine= "PARSER",
                cwe_ids      = ["CWE-78"] if "exec" in node["name"].lower()
                               else ["CWE-502"] if "pickle" in node["name"].lower()
                               else ["CWE-94"],
                confidence   = 0.70,
            ))

    ts = datetime.now(timezone.utc).isoformat()
    return UnifiedIR(
        target       = target,
        scan_id      = scan_id,
        timestamp    = ts,
        engines_used = ["PARSER"],
        findings     = findings,
        metadata     = ir_dict.get("metadata", {}),
    )


def from_url_scanner(ir_dict: dict[str, Any], scan_id: str) -> UnifiedIR:
    """
    Convert a url_scanner.py IR dict into UnifiedIR.
    """
    findings: list[UnifiedFinding] = []
    target = ir_dict.get("file", ir_dict.get("metadata", {}).get("target_url", "unknown"))
    n = 0

    for node in ir_dict.get("nodes", []):
        if node["type"] not in ("url_finding", "endpoint"):
            continue
        props = node.get("props", {})
        if not props.get("dangerous") and props.get("severity") not in ("CRITICAL", "HIGH"):
            continue

        n += 1
        findings.append(UnifiedFinding(
            id           = _uid("URL", n),
            severity     = props.get("severity", "MEDIUM"),
            category     = "HEADER" if "HEADER" in node["name"]
                          else "JS" if node["name"].startswith("JS_")
                          else "SECRET" if "SECRET" in node["name"]
                          else "ENDPOINT",
            title        = node["name"].replace("_", " ").title(),
            detail       = props.get("detail", ""),
            location     = props.get("url", target),
            source_engine= "URL_SCANNER",
            cwe_ids      = props.get("cwe_ids", ["CWE-200"]),
            confidence   = props.get("confidence", 0.8),
        ))

    ts = datetime.now(timezone.utc).isoformat()
    return UnifiedIR(
        target       = target,
        scan_id      = scan_id,
        timestamp    = ts,
        engines_used = ["URL_SCANNER"],
        findings     = findings,
        metadata     = ir_dict.get("metadata", {}),
    )


def merge(*irs: UnifiedIR) -> UnifiedIR:
    """
    Merge multiple UnifiedIR objects (from different engines scanning
    the same target) into one consolidated IR.
    """
    if not irs:
        raise ValueError("merge() requires at least one UnifiedIR")

    base = irs[0]
    all_findings: list[UnifiedFinding] = []
    all_engines:  list[str]            = []
    combined_meta: dict[str, Any]      = {}

    for ir in irs:
        all_findings.extend(ir.findings)
        for eng in ir.engines_used:
            if eng not in all_engines:
                all_engines.append(eng)
        combined_meta.update(ir.metadata)

    # Deduplicate by (location, title) — same finding from two engines
    seen: set[tuple[str, str]] = set()
    deduped: list[UnifiedFinding] = []
    for f in all_findings:
        key = (f.location, f.title)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return UnifiedIR(
        target       = base.target,
        scan_id      = base.scan_id,
        timestamp    = base.timestamp,
        engines_used = all_engines,
        findings     = deduped,
        metadata     = combined_meta,
    )
