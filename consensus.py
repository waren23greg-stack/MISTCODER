from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from findings import AttackChain, UnifiedFindings

MAX_FALLBACK_REMEDIATION_ITEMS = 5


def _signature(chain: AttackChain) -> str:
    cwes = ",".join(sorted(chain.cwe_mappings))
    return f"{chain.description.lower().strip()}|{cwes}"


@dataclass(frozen=True)
class ConsensusReport:
    high_confidence_truths: Tuple[str, ...]
    reconciled_risk_rankings: Tuple[Dict[str, object], ...]
    prioritized_remediation: Tuple[str, ...]
    audit_chain_tip: str
    consensus_hash: str
    audit_hash_chain: Tuple[str, ...] = field(default_factory=tuple)


def synthesize_consensus(findings: UnifiedFindings) -> ConsensusReport:
    phantom = findings.phantom.attack_chains if findings.phantom else ()
    oracle = findings.oracle.attack_chains if findings.oracle else ()
    covenant = findings.covenant.attack_chains if findings.covenant else ()

    phantom_map = {_signature(c): c for c in phantom}
    oracle_map = {_signature(c): c for c in oracle}
    covenant_map = {_signature(c): c for c in covenant}

    agreed_keys = sorted(
        set(phantom_map.keys()) & set(oracle_map.keys()) & set(covenant_map.keys())
    )
    truths = tuple(phantom_map[key].description for key in agreed_keys)

    merged: Dict[str, List[float]] = {}
    for group in (phantom_map, oracle_map, covenant_map):
        for key, chain in group.items():
            merged.setdefault(key, []).append(chain.severity_score)
    reconciled = []
    for key in sorted(merged):
        score = sum(merged[key]) / len(merged[key])
        source = phantom_map.get(key)
        if source is None:
            source = oracle_map.get(key)
        if source is None:
            source = covenant_map.get(key)
        reconciled.append(
            {
                "chain": source.description,
                "average_severity": round(score, 2),
                "cwe_mappings": tuple(sorted(source.cwe_mappings)),
            }
        )
    reconciled.sort(key=lambda row: (-float(row["average_severity"]), str(row["chain"])))

    remediation = findings.covenant.remediation if findings.covenant else ()
    if not remediation:
        remediation = tuple(
            f"Mitigate {entry['chain']}"
            for entry in reconciled[:MAX_FALLBACK_REMEDIATION_ITEMS]
            if entry["chain"]
        )

    audit_hashes = tuple(entry.entry_hash for entry in findings.audit_trail)
    audit_tip = audit_hashes[-1] if audit_hashes else ""
    consensus_payload = {
        "truths": truths,
        "reconciled": reconciled,
        "remediation": remediation,
    }
    consensus_hash = hashlib.sha256(
        json.dumps(consensus_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    return ConsensusReport(
        high_confidence_truths=truths,
        reconciled_risk_rankings=tuple(reconciled),
        prioritized_remediation=tuple(remediation),
        audit_chain_tip=audit_tip,
        consensus_hash=consensus_hash,
        audit_hash_chain=audit_hashes,
    )
