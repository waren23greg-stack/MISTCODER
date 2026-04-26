# blockchain/chain_persistence.py
# MISTCODER Threat-Native Blockchain
# Layer 5 — Chain Persistence
#
# Right now every run starts from Genesis.
# This changes that forever.
#
# MistChainPersistence saves the entire certified chain to disk
# after every run and reloads it on startup — so the chain
# accumulates history across every scan ever run.
#
# The chain only grows. It never resets. It never forgets.
#
# sandbox/
#   mistchain.json        ← the persistent chain (grows forever)
#   mistchain_index.json  ← fast lookup: finding_id → block number

import json
import time
from pathlib import Path
from datetime import datetime, timezone
from blockchain.block import Block
from blockchain.chain import MistChain

SANDBOX    = Path(__file__).resolve().parent.parent / "sandbox"
CHAIN_PATH = SANDBOX / "mistchain.json"
INDEX_PATH = SANDBOX / "mistchain_index.json"


class MistChainPersistence:
    """
    Saves and loads the MistChain to/from disk.

    Every certified finding is permanently recorded.
    Every restart picks up exactly where the last scan left off.
    The chain becomes a living audit ledger — growing with every run.
    """

    # ── Save ──────────────────────────────────────────────────────────────
    @staticmethod
    def save(chain: MistChain):
        """
        Serialise the entire chain to mistchain.json.
        Called automatically at the end of every scan.
        """
        SANDBOX.mkdir(exist_ok=True)

        blocks = []
        for block in chain.chain:
            blocks.append({
                "index"        : block.index,
                "timestamp"    : block.timestamp,
                "transactions" : block.transactions,
                "previous_hash": block.previous_hash,
                "nonce"        : block.nonce,
                "hash"         : block.hash
            })

        data = {
            "version"    : "1.0",
            "saved_at"   : datetime.now(timezone.utc).isoformat(),
            "difficulty" : chain.DIFFICULTY,
            "block_count": len(blocks),
            "blocks"     : blocks
        }

        with open(CHAIN_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        print(f"[PERSIST] Chain saved — {len(blocks)} blocks → mistchain.json")

        # Update the finding index
        MistChainPersistence._update_index(chain)

    # ── Load ──────────────────────────────────────────────────────────────
    @staticmethod
    def load() -> MistChain:
        """
        Restore a MistChain from mistchain.json.
        If no file exists — boots a fresh chain from Genesis.
        If file exists — rehydrates every block and verifies integrity.
        """
        if not CHAIN_PATH.exists():
            print("[PERSIST] No chain on disk — starting fresh from Genesis.")
            return MistChain()

        with open(CHAIN_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)

        saved_blocks = data.get("blocks", [])
        print(f"[PERSIST] Loading chain from disk — "
              f"{len(saved_blocks)} blocks found...")

        # Rehydrate
        chain        = MistChain.__new__(MistChain)
        chain.DIFFICULTY          = data.get("difficulty", 3)
        chain.chain               = []
        chain.pending_transactions = []

        for b in saved_blocks:
            block               = Block.__new__(Block)
            block.index         = b["index"]
            block.timestamp     = b["timestamp"]
            block.transactions  = b["transactions"]
            block.previous_hash = b["previous_hash"]
            block.nonce         = b["nonce"]
            block.hash          = b["hash"]
            chain.chain.append(block)

        # Verify the loaded chain
        if not chain.is_valid():
            print("[PERSIST] WARNING — loaded chain failed integrity check!")
            print("[PERSIST] Possible tampering detected. Starting fresh.")
            return MistChain()

        print(f"[PERSIST] Chain restored — integrity VERIFIED.")
        print(f"[PERSIST] Resuming from block {len(chain.chain) - 1}.")
        return chain

    # ── Index ─────────────────────────────────────────────────────────────
    @staticmethod
    def _update_index(chain: MistChain):
        """
        Build a fast lookup: finding_id → block_number.
        Lets you instantly answer: "which block certified KC-007?"
        """
        index = {}
        for block in chain.chain:
            for tx in block.transactions:
                if isinstance(tx, dict) and tx.get("tx_type") == "PHANTOM":
                    fid = tx.get("payload", {}).get("finding_id")
                    if fid:
                        index[fid] = {
                            "block"    : block.index,
                            "hash"     : block.hash[:24],
                            "timestamp": datetime.fromtimestamp(
                                block.timestamp, tz=timezone.utc
                            ).isoformat()
                        }

        with open(INDEX_PATH, "w", encoding="utf-8") as f:
            json.dump(index, f, indent=2)

        print(f"[PERSIST] Index updated — {len(index)} findings indexed.")

    # ── Query ─────────────────────────────────────────────────────────────
    @staticmethod
    def lookup(finding_id: str) -> dict:
        """
        Instantly look up which block certified a specific finding.
        Returns block number, hash, and timestamp.
        """
        if not INDEX_PATH.exists():
            return {}
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            index = json.load(f)
        return index.get(finding_id, {})

    # ── Stats ─────────────────────────────────────────────────────────────
    @staticmethod
    def stats() -> dict:
        """Return chain statistics from disk without loading the full chain."""
        if not CHAIN_PATH.exists():
            return {"status": "no chain on disk"}
        with open(CHAIN_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {
            "status"     : "persisted",
            "saved_at"   : data.get("saved_at"),
            "block_count": data.get("block_count", 0),
            "difficulty" : data.get("difficulty", 3)
        }