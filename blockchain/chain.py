# blockchain/chain.py
# MISTCODER Threat-Native Blockchain
# Layer 1 — MistChain: the linked structure that makes history immutable
#
# The chain does three things:
#   1. Holds all blocks in order
#   2. Enforces that every block correctly references the one before it
#   3. Runs Proof of Threat mining before accepting a new block

from blockchain.block import Block
from blockchain.transaction import CertificateRecord


class MistChain:
    """
    The MISTCODER threat chain.

    Rules:
      - Block 0 is the Genesis block (no findings, just an anchor)
      - Every new block must reference the previous block's hash
      - A block is REJECTED if it contains an uncertified finding
        (i.e. no matching COVENANT CertificateRecord with certified=True)
      - Proof of Threat difficulty: hash must start with leading zeros
    """

    DIFFICULTY = 3  # hash must start with '000'

    def __init__(self):
        self.chain             = []
        self.pending_transactions = []
        self._create_genesis_block()

    # ── Genesis ──────────────────────────────────────────────────────────
    def _create_genesis_block(self):
        """
        Block 0. The anchor of the entire chain.
        No transactions. Previous hash is all zeros.
        """
        genesis = Block(
            index=0,
            transactions=[{"type": "GENESIS", "message": "MISTCODER chain initialised"}],
            previous_hash="0" * 64
        )
        genesis.hash = self._proof_of_threat(genesis)
        self.chain.append(genesis)
        print(f"[CHAIN] Genesis block mined: {genesis.hash[:16]}...")

    # ── Proof of Threat ───────────────────────────────────────────────────
    def _proof_of_threat(self, block):
        """
        Mine the block: increment nonce until hash starts
        with DIFFICULTY leading zeros.

        This is the consensus work that makes forging a block expensive.
        In MISTCODER this represents the adversarial effort required
        to fabricate a threat finding — it has a real computational cost.
        """
        block.nonce = 0
        computed = block.compute_hash()
        while not computed.startswith("0" * self.DIFFICULTY):
            block.nonce += 1
            computed = block.compute_hash()
        return computed

    # ── COVENANT gate ─────────────────────────────────────────────────────
    def _covenant_gate(self, transactions):
        """
        COVENANT constitutional check.
        A block cannot be committed unless at least one
        CertificateRecord with certified=True exists in its transactions.

        This is the architectural guarantee: PHANTOM cannot write to the
        chain without COVENANT's sign-off. Ever.
        """
        for tx in transactions:
            if (tx.get("tx_type") == "COVENANT" and
                    tx.get("payload", {}).get("certified") is True):
                return True
        return False

    # ── Add transactions ──────────────────────────────────────────────────
    def add_transaction(self, transaction):
        """Stage a transaction for the next block."""
        self.pending_transactions.append(transaction.to_dict())
        print(f"[CHAIN] Staged: {transaction.tx_type} tx {transaction.tx_id}")

    # ── Mine block ────────────────────────────────────────────────────────
    def mine_block(self):
        """
        Commit all pending transactions into a new block.
        Steps:
          1. COVENANT gate — reject if uncertified
          2. Create block referencing previous hash
          3. Run Proof of Threat (mine)
          4. Append to chain
        """
        if not self.pending_transactions:
            print("[CHAIN] No pending transactions to mine.")
            return None

        # Step 1 — COVENANT gate
        if not self._covenant_gate(self.pending_transactions):
            print("[CHAIN] REJECTED — no valid COVENANT certificate found.")
            print("[CHAIN] Block will NOT be committed to the chain.")
            return None

        # Step 2 — Build block
        previous_block = self.chain[-1]
        new_block = Block(
            index=len(self.chain),
            transactions=self.pending_transactions,
            previous_hash=previous_block.hash
        )

        # Step 3 — Mine
        print(f"[CHAIN] Mining block {new_block.index}...")
        new_block.hash = self._proof_of_threat(new_block)
        print(f"[CHAIN] Block {new_block.index} mined after {new_block.nonce} iterations.")

        # Step 4 — Commit
        self.chain.append(new_block)
        self.pending_transactions = []
        print(f"[CHAIN] Block {new_block.index} committed: {new_block.hash[:16]}...")
        return new_block

    # ── Integrity check ───────────────────────────────────────────────────
    def is_valid(self):
        """
        Walk the entire chain and verify:
          1. Each block's stored hash matches its recomputed hash
          2. Each block's previous_hash matches the actual previous block
        If either fails anywhere — the chain is compromised.
        """
        for i in range(1, len(self.chain)):
            current  = self.chain[i]
            previous = self.chain[i - 1]

            if current.hash != current.compute_hash():
                print(f"[CHAIN] TAMPER DETECTED at block {i} — hash mismatch!")
                return False

            if current.previous_hash != previous.hash:
                print(f"[CHAIN] TAMPER DETECTED at block {i} — broken link!")
                return False

        print("[CHAIN] Chain integrity: VERIFIED")
        return True

    def __repr__(self):
        return f"MistChain(blocks={len(self.chain)}, difficulty={self.DIFFICULTY})"