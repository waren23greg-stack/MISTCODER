# blockchain/block.py
# MISTCODER Threat-Native Blockchain
# Layer 1 — Block: the atomic unit of the chain
# Every MISTCODER scan produces one Block.

import hashlib
import json
import time


class Block:
    """
    A single block in the MISTCODER threat chain.

    Each block carries:
      - index        : its position in the chain
      - timestamp    : when the scan was certified
      - transactions : list of ThreatTransactions (findings, kill chains)
      - previous_hash: cryptographic link to the block before it
      - nonce        : the number that satisfies Proof of Threat
      - hash         : this block's own fingerprint
    """

    def __init__(self, index, transactions, previous_hash):
        self.index         = index
        self.timestamp     = time.time()
        self.transactions  = transactions   # list of dicts
        self.previous_hash = previous_hash
        self.nonce         = 0
        self.hash          = self.compute_hash()

    def compute_hash(self):
        """
        SHA-256 fingerprint of this block's entire contents.
        Change one character anywhere — the hash changes completely.
        This is the tamper-evidence guarantee COVENANT relies on.
        """
        block_data = json.dumps({
            "index"        : self.index,
            "timestamp"    : self.timestamp,
            "transactions" : self.transactions,
            "previous_hash": self.previous_hash,
            "nonce"        : self.nonce
        }, sort_keys=True)

        return hashlib.sha256(block_data.encode()).hexdigest()

    def __repr__(self):
        return (
            f"Block(index={self.index}, "
            f"hash={self.hash[:12]}..., "
            f"prev={self.previous_hash[:12]}..., "
            f"txns={len(self.transactions)})"
        )