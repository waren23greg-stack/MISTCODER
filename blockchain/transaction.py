# blockchain/transaction.py
# MISTCODER Threat-Native Blockchain
# Layer 1 — ThreatTransaction: what lives inside each Block
#
# In Bitcoin, transactions move money.
# In MISTCODER, transactions carry certified threat intelligence.
# Three transaction types mirror the Trinity:
#   PHANTOM  → ThreatFinding      (a discovered kill chain)
#   ORACLE   → IntelVerdict       (confidence score + CVE cross-ref)
#   COVENANT → CertificateRecord  (cryptographic sign-off)

import hashlib
import json
import time


class ThreatTransaction:
    """
    Base transaction. Every finding that enters the chain
    is wrapped in one of the three subclasses below.
    """

    def __init__(self, tx_type, payload):
        self.tx_type   = tx_type    # "PHANTOM" | "ORACLE" | "COVENANT"
        self.payload   = payload    # dict of finding data
        self.timestamp = time.time()
        self.tx_id     = self._generate_id()

    def _generate_id(self):
        """
        Unique ID for this transaction.
        Built from type + payload + timestamp so it's
        deterministic and tamper-evident.
        """
        raw = json.dumps({
            "tx_type"  : self.tx_type,
            "payload"  : self.payload,
            "timestamp": self.timestamp
        }, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self):
        """Serialise for storage inside a Block."""
        return {
            "tx_id"    : self.tx_id,
            "tx_type"  : self.tx_type,
            "payload"  : self.payload,
            "timestamp": self.timestamp
        }

    def __repr__(self):
        return f"ThreatTransaction(type={self.tx_type}, id={self.tx_id})"


class ThreatFinding(ThreatTransaction):
    """
    PHANTOM's output.
    Carries one kill chain: its steps, score, and stealth rating.
    """

    def __init__(self, finding_id, steps, score, stealth, novelty):
        payload = {
            "finding_id": finding_id,
            "steps"     : steps,      # list of CWEs / attack steps
            "score"     : score,      # Impact × Stealth × Novelty
            "stealth"   : stealth,    # 0.0 – 1.0
            "novelty"   : novelty     # 0.0 – 1.0
        }
        super().__init__("PHANTOM", payload)


class IntelVerdict(ThreatTransaction):
    """
    ORACLE's output.
    Challenges PHANTOM's finding against the world model.
    Produces a confidence score and CVE cross-references.
    """

    def __init__(self, finding_id, confidence, cve_refs, verdict):
        payload = {
            "finding_id": finding_id,
            "confidence": confidence,   # 0.0 – 1.0
            "cve_refs"  : cve_refs,     # list of CVE IDs
            "verdict"   : verdict       # "CONFIRMED" | "DISPUTED" | "NOVEL"
        }
        super().__init__("ORACLE", payload)


class CertificateRecord(ThreatTransaction):
    """
    COVENANT's output.
    The constitutional sign-off. Without this, a finding
    cannot be committed to the chain.
    """

    def __init__(self, finding_id, certified, reason, jurisdiction):
        payload = {
            "finding_id" : finding_id,
            "certified"  : certified,     # True | False
            "reason"     : reason,        # why certified or blocked
            "jurisdiction": jurisdiction  # e.g. "CFAA" | "GDPR" | "OPEN"
        }
        super().__init__("COVENANT", payload)