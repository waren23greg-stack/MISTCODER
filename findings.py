from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Tuple


def _clamp_0_100(value: float) -> float:
    return max(0.0, min(100.0, float(value)))


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


@dataclass(frozen=True)
class ThreatVector:
    name: str
    impact: float
    stealth: float
    novelty: float
    rationale: str = ""

    @property
    def rank_score(self) -> float:
        return _clamp_0_100((self.impact * self.stealth * self.novelty) / 10_000.0)


@dataclass(frozen=True)
class AttackChain:
    chain_id: str
    description: str
    severity_score: float
    steps: Tuple[str, ...] = field(default_factory=tuple)
    threat_vectors: Tuple[ThreatVector, ...] = field(default_factory=tuple)
    cwe_mappings: Tuple[str, ...] = field(default_factory=tuple)
    owasp_mappings: Tuple[str, ...] = field(default_factory=tuple)

    def normalized(self) -> "AttackChain":
        vectors = tuple(
            sorted(self.threat_vectors, key=lambda v: (-v.rank_score, v.name.lower()))
        )
        return AttackChain(
            chain_id=self.chain_id,
            description=self.description,
            severity_score=_clamp_0_100(self.severity_score),
            steps=tuple(self.steps),
            threat_vectors=vectors,
            cwe_mappings=tuple(sorted(set(self.cwe_mappings))),
            owasp_mappings=tuple(sorted(set(self.owasp_mappings))),
        )


@dataclass(frozen=True)
class StageFindings:
    engine: str
    summary: str
    attack_chains: Tuple[AttackChain, ...] = field(default_factory=tuple)
    remediation: Tuple[str, ...] = field(default_factory=tuple)
    raw: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AuditTrailEntry:
    index: int
    stage: str
    event: str
    timestamp_utc: str
    payload_hash: str
    prev_hash: str
    entry_hash: str

    @staticmethod
    def create(
        index: int, stage: str, event: str, payload: Mapping[str, Any], prev_hash: str
    ) -> "AuditTrailEntry":
        payload_hash = hashlib.sha256(_canonical_json(payload).encode()).hexdigest()
        raw = {
            "index": index,
            "stage": stage,
            "event": event,
            "payload_hash": payload_hash,
            "prev_hash": prev_hash,
        }
        entry_hash = hashlib.sha256(_canonical_json(raw).encode()).hexdigest()
        return AuditTrailEntry(
            index=index,
            stage=stage,
            event=event,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            payload_hash=payload_hash,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )


@dataclass(frozen=True)
class UnifiedFindings:
    session_id: str
    phantom: Optional[StageFindings] = None
    oracle: Optional[StageFindings] = None
    covenant: Optional[StageFindings] = None
    token_spend: Mapping[str, int] = field(default_factory=dict)
    audit_trail: Tuple[AuditTrailEntry, ...] = field(default_factory=tuple)
    warnings: Tuple[str, ...] = field(default_factory=tuple)
    errors: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def stage_findings_from_dict(engine: str, payload: Mapping[str, Any]) -> StageFindings:
    attack_chains = []
    for i, chain in enumerate(payload.get("attack_chains", ())):
        vectors = []
        for vector in chain.get("threat_vectors", ()):
            vectors.append(
                ThreatVector(
                    name=str(vector.get("name", f"vector-{i}")),
                    impact=_clamp_0_100(vector.get("impact", 0)),
                    stealth=_clamp_0_100(vector.get("stealth", 0)),
                    novelty=_clamp_0_100(vector.get("novelty", 0)),
                    rationale=str(vector.get("rationale", "")),
                )
            )
        attack_chains.append(
            AttackChain(
                chain_id=str(chain.get("chain_id", f"{engine.lower()}-{i + 1}")),
                description=str(chain.get("description", "")),
                severity_score=_clamp_0_100(chain.get("severity_score", 0)),
                steps=tuple(str(step) for step in chain.get("steps", ())),
                threat_vectors=tuple(vectors),
                cwe_mappings=tuple(str(c) for c in chain.get("cwe_mappings", ())),
                owasp_mappings=tuple(str(o) for o in chain.get("owasp_mappings", ())),
            ).normalized()
        )
    return StageFindings(
        engine=engine,
        summary=str(payload.get("summary", "")),
        attack_chains=tuple(
            sorted(attack_chains, key=lambda c: (-c.severity_score, c.chain_id))
        ),
        remediation=tuple(str(x) for x in payload.get("remediation", ())),
        raw=dict(payload),
    )
