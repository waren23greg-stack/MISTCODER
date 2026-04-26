# blockchain/chain_viewer.py
# MISTCODER Threat-Native Blockchain
# Chain Viewer CLI — inspect any block or finding by ID
#
# Usage:
#   python -m blockchain.chain_viewer              → full ledger
#   python -m blockchain.chain_viewer block 4      → single block
#   python -m blockchain.chain_viewer find PATH-0004→ finding lookup
#   python -m blockchain.chain_viewer stats        → chain statistics
#   python -m blockchain.chain_viewer verify       → integrity check

import sys
import json
from datetime import datetime, timezone
from pathlib import Path
from blockchain.chain_persistence import MistChainPersistence

SANDBOX = Path(__file__).resolve().parent.parent / "sandbox"


def fmt_time(ts):
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)\
                       .strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def print_block(block, detail=True):
    print(f"  ┌─ Block {block.index} {'─' * 48}")
    print(f"  │  Time     : {fmt_time(block.timestamp)}")
    print(f"  │  Hash     : {block.hash}")
    print(f"  │  Prev     : {block.previous_hash}")
    print(f"  │  Nonce    : {block.nonce}")
    print(f"  │  Txns     : {len(block.transactions)}")

    if detail:
        for tx in block.transactions:
            if isinstance(tx, dict):
                tx_type = tx.get("tx_type", tx.get("type", "UNKNOWN"))
                tx_id   = tx.get("tx_id", "")
                payload = tx.get("payload", {})

                if tx_type == "GENESIS":
                    print(f"  │  └─ GENESIS — {tx.get('message','')}")
                elif tx_type == "PHANTOM":
                    fid   = payload.get("finding_id", "")
                    score = payload.get("score", "")
                    steps = payload.get("steps", [])
                    print(f"  │  └─ PHANTOM  [{tx_id[:12]}]")
                    print(f"  │       Finding : {fid}")
                    print(f"  │       Score   : {score}")
                    print(f"  │       Steps   : {' → '.join(steps)}")
                elif tx_type == "ORACLE":
                    fid        = payload.get("finding_id", "")
                    confidence = payload.get("confidence", "")
                    verdict    = payload.get("verdict", "")
                    cves       = payload.get("cve_refs", [])
                    print(f"  │  └─ ORACLE   [{tx_id[:12]}]")
                    print(f"  │       Finding : {fid}")
                    print(f"  │       Verdict : {verdict} ({confidence})")
                    if cves:
                        print(f"  │       CVEs    : {', '.join(cves)}")
                elif tx_type == "COVENANT":
                    fid      = payload.get("finding_id", "")
                    cert     = payload.get("certified", False)
                    reason   = payload.get("reason", "")
                    status   = "✓ CERTIFIED" if cert else "✗ REJECTED"
                    print(f"  │  └─ COVENANT [{tx_id[:12]}]")
                    print(f"  │       Finding : {fid}")
                    print(f"  │       Status  : {status}")
                    print(f"  │       Reason  : {reason}")

    print(f"  └{'─' * 54}")
    print()


def cmd_ledger():
    """Print the full chain ledger."""
    chain = MistChainPersistence.load()
    blocks = chain.chain

    print()
    print("═" * 60)
    print("  MISTCODER THREAT CHAIN — FULL LEDGER")
    print("═" * 60)
    print(f"  Blocks    : {len(blocks)}")
    print(f"  Difficulty: {chain.DIFFICULTY}")
    print()

    for block in blocks:
        print_block(block, detail=True)

    chain.is_valid()


def cmd_block(index):
    """Print a single block by index."""
    chain  = MistChainPersistence.load()
    blocks = chain.chain

    try:
        idx = int(index)
    except ValueError:
        print(f"[VIEWER] Invalid block index: {index}")
        return

    if idx < 0 or idx >= len(blocks):
        print(f"[VIEWER] Block {idx} not found. "
              f"Chain has {len(blocks)} blocks (0–{len(blocks)-1}).")
        return

    print()
    print("═" * 60)
    print(f"  BLOCK {idx} DETAIL")
    print("═" * 60)
    print()
    print_block(blocks[idx], detail=True)


def cmd_find(finding_id):
    """Look up a finding by ID and show its block."""
    record = MistChainPersistence.lookup(finding_id)

    if not record:
        print(f"\n[VIEWER] Finding '{finding_id}' not found in chain index.")
        print("[VIEWER] Run python -m blockchain.chain_exporter first.")
        return

    print()
    print("═" * 60)
    print(f"  FINDING LOOKUP — {finding_id}")
    print("═" * 60)
    print(f"  Certified at : {record.get('timestamp','')[:19]} UTC")
    print(f"  Block        : {record['block']}")
    print(f"  Block hash   : {record['hash']}...")
    print()

    # Load full block detail
    chain = MistChainPersistence.load()
    block_idx = record["block"]
    if block_idx < len(chain.chain):
        print_block(chain.chain[block_idx], detail=True)


def cmd_stats():
    """Print chain statistics and OracleBrain state."""
    stats = MistChainPersistence.stats()
    print()
    print("═" * 60)
    print("  MISTCODER CHAIN STATISTICS")
    print("═" * 60)
    print(f"  Status      : {stats.get('status')}")
    print(f"  Saved at    : {stats.get('saved_at','')[:19]} UTC")
    print(f"  Blocks      : {stats.get('block_count')}")
    print(f"  Difficulty  : {stats.get('difficulty')}")
    print()

    # Index stats
    index_path = SANDBOX / "mistchain_index.json"
    if index_path.exists():
        with open(index_path) as f:
            index = json.load(f)
        print(f"  Indexed findings : {len(index)}")
        print()
        print("  Finding → Block map:")
        for fid, rec in sorted(index.items()):
            print(f"    {fid} → block {rec['block']} "
                  f"| {rec['timestamp'][:10]} "
                  f"| {rec['hash']}...")

    # OracleBrain stats
    kb_path = SANDBOX / "oracle_knowledge.json"
    co_path = SANDBOX / "oracle_cooccurrence.json"
    inc_path = SANDBOX / "oracle_incubation.json"
    vel_path = SANDBOX / "oracle_velocity.json"
    sig_path = SANDBOX / "oracle_signatures.json"

    print()
    print("  OracleBrain state:")
    if kb_path.exists():
        with open(kb_path) as f:
            kb = json.load(f)
        print(f"    Known patterns    : {len(kb)}")
        top = sorted(kb.items(), key=lambda x: -x[1].get("confidence", 0))[:3]
        for k, v in top:
            print(f"      {k}: confidence={v['confidence']} "
                  f"sightings={v.get('sightings',0)}")

    if co_path.exists():
        with open(co_path) as f:
            co = json.load(f)
        print(f"    Co-occurrence pairs: {len(co)}")

    if inc_path.exists():
        with open(inc_path) as f:
            inc = json.load(f)
        incubating = [k for k, v in inc.items()
                      if v.get("status") == "INCUBATING"]
        promoted   = [k for k, v in inc.items()
                      if v.get("status") == "PROMOTED"]
        print(f"    Incubating novel  : {len(incubating)}")
        print(f"    Self-promoted     : {len(promoted)}")

    if vel_path.exists():
        with open(vel_path) as f:
            vel = json.load(f)
        rising = [k for k, v in vel.items() if v.get("trend") == "RISING"]
        if rising:
            print(f"    RISING threats    : {rising}")

    if sig_path.exists():
        with open(sig_path) as f:
            sig = json.load(f)
        print(f"    Adv. signatures   : {len(sig)}")

    print()


def cmd_verify():
    """Run integrity check on the full chain."""
    print()
    print("═" * 60)
    print("  CHAIN INTEGRITY VERIFICATION")
    print("═" * 60)
    chain = MistChainPersistence.load()
    valid = chain.is_valid()
    print(f"  Blocks checked : {len(chain.chain)}")
    print(f"  Result         : {'✓ VERIFIED' if valid else '✗ COMPROMISED'}")
    print()


def usage():
    print("""
MISTCODER Chain Viewer

  python -m blockchain.chain_viewer              full ledger
  python -m blockchain.chain_viewer block <N>    single block by index
  python -m blockchain.chain_viewer find <ID>    finding lookup by ID
  python -m blockchain.chain_viewer stats        chain + oracle stats
  python -m blockchain.chain_viewer verify       integrity check
""")


if __name__ == "__main__":
    args = sys.argv[1:]

    if not args:
        cmd_ledger()
    elif args[0] == "block" and len(args) >= 2:
        cmd_block(args[1])
    elif args[0] == "find" and len(args) >= 2:
        cmd_find(args[1])
    elif args[0] == "stats":
        cmd_stats()
    elif args[0] == "verify":
        cmd_verify()
    else:
        usage()