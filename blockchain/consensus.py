# blockchain/consensus.py
# MISTCODER Threat-Native Blockchain
# Layer 1 — Proof of Threat Consensus
#
# The rule: a kill chain is only CANONICAL when
# DIFFICULTY_NODES independent nodes reproduce the same finding.
#
# One PHANTOM can be wrong.
# Three PHANTOMs agreeing cannot all be wrong.
#
# This is what separates MISTCODER from every other scanner:
# findings are not claimed — they are AGREED UPON.

import hashlib
import json


# How many independent nodes must confirm a finding
# before it becomes canonical truth on the chain.
CONSENSUS_THRESHOLD = 2  # start at 2, raise to 3+ in production


class ThreatConsensus:
    """
    Tracks votes from independent PHANTOM nodes on each kill chain.

    Flow:
      1. Node submits a vote: "I found kill chain KC-001 with score 8.31"
      2. ThreatConsensus tallies votes per finding_id
      3. When CONSENSUS_THRESHOLD votes agree — finding is CANONICAL
      4. Canonical findings are cleared for COVENANT certification
      5. Disputed findings are flagged and never reach the chain
    """

    def __init__(self):
        # finding_id → list of votes from different nodes
        self.votes     = {}
        # finding_id → True/False once threshold is reached
        self.canonical = {}

    # ── Submit a vote ─────────────────────────────────────────────────────
    def submit_vote(self, node_id, finding_id, steps, score):
        """
        A PHANTOM node votes that it found a specific kill chain.

        node_id    : unique ID of the scanning node
        finding_id : kill chain identifier e.g. 'KC-001'
        steps      : the exact attack steps found
        score      : Impact × Stealth × Novelty score
        """
        if finding_id not in self.votes:
            self.votes[finding_id] = []

        # Fingerprint this vote — same steps must produce same fingerprint
        # across all nodes for consensus to trigger
        fingerprint = self._fingerprint(steps, score)

        vote = {
            "node_id"    : node_id,
            "finding_id" : finding_id,
            "fingerprint": fingerprint,
            "score"      : score,
            "steps"      : steps
        }

        # Prevent duplicate votes from same node
        existing_nodes = [v["node_id"] for v in self.votes[finding_id]]
        if node_id in existing_nodes:
            print(f"[CONSENSUS] Node {node_id} already voted on {finding_id} — ignored.")
            return

        self.votes[finding_id].append(vote)
        print(f"[CONSENSUS] Vote received: node={node_id}, finding={finding_id}, "
              f"fingerprint={fingerprint[:12]}...")

        # Check if threshold is reached
        self._evaluate(finding_id)

    # ── Evaluate consensus ────────────────────────────────────────────────
    def _evaluate(self, finding_id):
        """
        Count how many votes share the same fingerprint.
        If CONSENSUS_THRESHOLD votes match — mark as CANONICAL.
        If votes conflict — mark as DISPUTED.
        """
        votes = self.votes[finding_id]

        # Tally fingerprints
        tally = {}
        for vote in votes:
            fp = vote["fingerprint"]
            tally[fp] = tally.get(fp, 0) + 1

        # Check for consensus
        for fp, count in tally.items():
            if count >= CONSENSUS_THRESHOLD:
                self.canonical[finding_id] = True
                print(f"[CONSENSUS] ✓ CANONICAL — {finding_id} confirmed by "
                      f"{count}/{len(votes)} nodes. Ready for COVENANT.")
                return

        # Check for conflict
        if len(tally) > 1:
            self.canonical[finding_id] = False
            print(f"[CONSENSUS] ✗ DISPUTED — {finding_id} has conflicting "
                  f"votes. Will NOT reach the chain.")
            return

        # Still waiting for more votes
        print(f"[CONSENSUS] Waiting — {finding_id} has "
              f"{len(votes)}/{CONSENSUS_THRESHOLD} votes so far.")

    # ── Query status ──────────────────────────────────────────────────────
    def is_canonical(self, finding_id):
        """Returns True only if finding reached full consensus."""
        return self.canonical.get(finding_id, False)

    def is_disputed(self, finding_id):
        """Returns True if nodes disagreed on this finding."""
        return self.canonical.get(finding_id) is False

    # ── Fingerprint ───────────────────────────────────────────────────────
    def _fingerprint(self, steps, score):
        """
        Deterministic hash of attack steps + score.
        Two nodes that independently find the same kill chain
        will produce the identical fingerprint.
        This is the agreement mechanism.
        """
        raw = json.dumps({
            "steps": sorted(steps),  # sort so order doesn't matter
            "score": round(score, 2) # round so float drift doesn't break consensus
        }, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()

    def __repr__(self):
        total    = len(self.votes)
        canon    = sum(1 for v in self.canonical.values() if v)
        disputed = sum(1 for v in self.canonical.values() if not v)
        return (f"ThreatConsensus(findings={total}, "
                f"canonical={canon}, disputed={disputed})")