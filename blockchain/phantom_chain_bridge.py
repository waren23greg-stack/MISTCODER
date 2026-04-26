# blockchain/phantom_chain_bridge.py
# MISTCODER Threat-Native Blockchain
# Layer 2 — PhantomChainBridge (OracleBrain edition)

import json
import hashlib
import time
from blockchain.chain import MistChain
from blockchain.transaction import ThreatFinding, IntelVerdict, CertificateRecord
from blockchain.consensus import ThreatConsensus


class PhantomChainBridge:

    def __init__(self, node_id="NODE-PRIMARY"):
        self.node_id      = node_id
        self.chain        = MistChain()
        self.consensus    = ThreatConsensus()
        self.oracle_brain = self._init_brain()
        print(f"[BRIDGE] PhantomChainBridge online — node={self.node_id}")
        print(f"[BRIDGE] {self.chain}")
        print()

    # ── Oracle Brain init ─────────────────────────────────────────────────
    def _init_brain(self):
        from blockchain.oracle_brain import OracleBrain
        return OracleBrain(verbose=True)

    # ── Step 1: PHANTOM submits a finding ─────────────────────────────────
    def phantom_submit(self, finding_id, steps, score, stealth, novelty,
                       second_node_id="NODE-SECONDARY"):
        print(f"[BRIDGE] ═══ Processing {finding_id} ═══")
        print(f"[BRIDGE] Steps: {steps}")
        print(f"[BRIDGE] Score: {score} | Stealth: {stealth} | Novelty: {novelty}")
        print()

        self.consensus.submit_vote(self.node_id, finding_id, steps, score)
        self.consensus.submit_vote(second_node_id, finding_id, steps, score)

        if not self.consensus.is_canonical(finding_id):
            print(f"[BRIDGE] BLOCKED at consensus — {finding_id} not canonical.")
            return None

        print()
        return self._oracle_evaluate(finding_id, steps, score, stealth, novelty)

    # ── Step 2: ORACLE Brain evaluates ───────────────────────────────────
    def _oracle_evaluate(self, finding_id, steps, score, stealth, novelty):
        print(f"[ORACLE BRAIN] Evaluating {finding_id} against living world model...")

        result     = self.oracle_brain.evaluate(finding_id, steps, score)
        confidence = result["confidence"]
        cve_refs   = result["cve_refs"]
        verdict    = result["verdict"]

        return self._covenant_certify(
            finding_id, steps, score, stealth, novelty,
            confidence, cve_refs, verdict
        )

    # ── Step 3: COVENANT certifies ────────────────────────────────────────
    def _covenant_certify(self, finding_id, steps, score, stealth, novelty,
                          confidence, cve_refs, verdict):
        print(f"[COVENANT] Constitutional review of {finding_id}...")

        certified    = False
        reason       = ""
        jurisdiction = "OPEN"

        if score < 5.0:
            reason = f"Score {score} below actionable threshold of 5.0"
        elif confidence < 0.70:
            reason = f"ORACLE confidence {confidence} too low"
        elif verdict == "DISPUTED":
            reason = "ORACLE verdict DISPUTED — cannot certify"
        else:
            certified    = True
            reason       = f"Score {score} meets threshold. ORACLE {verdict} at {confidence}."
            jurisdiction = "CFAA"

        status = "CERTIFIED" if certified else "REJECTED"
        print(f"[COVENANT] {status} — {reason}")
        print()

        return self._commit_to_chain(
            finding_id, steps, score, stealth, novelty,
            confidence, cve_refs, verdict,
            certified, reason, jurisdiction
        )

    # ── Step 4: Commit to chain ───────────────────────────────────────────
    def _commit_to_chain(self, finding_id, steps, score, stealth, novelty,
                         confidence, cve_refs, verdict,
                         certified, reason, jurisdiction):
        tx_phantom  = ThreatFinding(finding_id, steps, score, stealth, novelty)
        tx_oracle   = IntelVerdict(finding_id, confidence, cve_refs, verdict)
        tx_covenant = CertificateRecord(finding_id, certified, reason, jurisdiction)

        self.chain.add_transaction(tx_phantom)
        self.chain.add_transaction(tx_oracle)
        self.chain.add_transaction(tx_covenant)
        print()

        block = self.chain.mine_block()
        print()

        if block:
            print(f"[BRIDGE] ✓ {finding_id} permanently on chain.")
            print(f"[BRIDGE] Block {block.index} | Hash: {block.hash[:24]}...")
        else:
            print(f"[BRIDGE] ✗ {finding_id} blocked — not committed.")

        print()
        return block

    # ── Full chain report ─────────────────────────────────────────────────
    def report(self):
        print("═" * 60)
        print("MISTCODER THREAT CHAIN — FINAL REPORT")
        print("═" * 60)
        self.chain.is_valid()
        print(f"Blocks committed : {len(self.chain.chain)}")
        print(f"Consensus state  : {self.consensus}")
        print("═" * 60)