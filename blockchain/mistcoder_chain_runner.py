# blockchain/mistcoder_chain_runner.py
# MISTCODER Threat-Native Blockchain
# Layer 3 — MistcoderChainRunner (with Layer 5 persistence + deduplication)
#
# Deduplication guard: before submitting any kill chain to the Trinity,
# check the chain index. If this finding_id was already certified in a
# previous run — skip it. The chain never double-certifies anything.
#
# A finding certified once is certified forever. The chain remembers.

import json
from pathlib import Path
from blockchain.phantom_chain_bridge import PhantomChainBridge
from blockchain.chain_persistence import MistChainPersistence

KNOWN_CWES = {
    "CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-200",
    "CWE-312", "CWE-502", "CWE-20", "CWE-94", "CWE-611",
}

SEVERITY_STEALTH = {
    "CRITICAL": 0.92,
    "HIGH"    : 0.75,
    "MEDIUM"  : 0.55,
    "LOW"     : 0.30,
    "INFO"    : 0.10,
}


class MistcoderChainRunner:

    def __init__(self, report_path=None, node_id="NODE-PRIMARY"):
        self.node_id = node_id

        # ── Layer 5: Load persisted chain from disk ───────────────────────
        print("[PERSIST] Checking for existing chain on disk...")
        print(f"[PERSIST] Chain stats: {MistChainPersistence.stats()}")
        loaded_chain = MistChainPersistence.load()

        # Boot bridge and inject the persisted chain
        self.bridge       = PhantomChainBridge(node_id=node_id)
        self.bridge.chain = loaded_chain

        root = Path(__file__).resolve().parent.parent
        self.report_path = Path(report_path) if report_path else \
                           root / "sandbox" / "phantom_report.json"

        self.results = {
            "certified"  : [],
            "blocked"    : [],
            "deduplicated": [],   # ← findings skipped because already on chain
            "scan_id"    : None
        }

    # ── Deduplication check ───────────────────────────────────────────────
    def _already_certified(self, finding_id: str) -> dict:
        """
        Check the chain index for this finding_id.
        Returns the existing block record if found, empty dict if not.

        This is the guard: if a kill chain was certified in any previous
        scan, it will never be submitted to Trinity again.
        The chain record is proof enough.
        """
        return MistChainPersistence.lookup(finding_id)

    def _load_report(self):
        if not self.report_path.exists():
            raise FileNotFoundError(
                f"[RUNNER] phantom_report.json not found at {self.report_path}"
            )
        with open(self.report_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _extract_steps(self, nodes):
        steps, seen = [], set()
        for node in nodes:
            if isinstance(node, dict):
                for key in ("call_name", "cwe_id"):
                    val = node.get(key, "")
                    if val and val not in seen:
                        steps.append(val)
                        seen.add(val)
        return steps if steps else ["unknown_step"]

    def _compute_stealth(self, nodes):
        scores = [
            SEVERITY_STEALTH.get(n.get("severity", "MEDIUM").upper(), 0.55)
            for n in nodes if isinstance(n, dict)
        ]
        return round(sum(scores) / len(scores), 2) if scores else 0.55

    def _compute_novelty(self, nodes):
        cwes = [n.get("cwe_id", "") for n in nodes
                if isinstance(n, dict) and n.get("cwe_id")]
        if not cwes:
            return 0.50
        return round(sum(1 for c in cwes if c not in KNOWN_CWES) / len(cwes), 2)

    def _compute_score(self, path, nodes):
        if path.get("score"):
            return round(float(path["score"]), 2)
        cvss = [n.get("cvss_score", 5.0) for n in nodes if isinstance(n, dict)]
        return round(sum(cvss) / len(cvss), 2) if cvss else 5.0

    def run(self):
        print("[RUNNER] Loading real PHANTOM scan report...")
        report       = self._load_report()
        attack_paths = report.get("attack_paths", [])

        self.results["scan_id"] = report.get("scan_id", "UNKNOWN")
        print(f"[RUNNER] Scan ID    : {self.results['scan_id']}")
        print(f"[RUNNER] TKG nodes  : {report.get('tkg', {}).get('nodes', '?')}")
        print(f"[RUNNER] TKG edges  : {report.get('tkg', {}).get('edges', '?')}")
        print(f"[RUNNER] Kill chains: {len(attack_paths)}")
        print(f"[RUNNER] Chain start: block {len(self.bridge.chain.chain) - 1}")
        print()

        if not attack_paths:
            print("[RUNNER] No attack paths found.")
            return self.results

        for path in attack_paths:
            finding_id = path.get("path_id") or path.get("id", "PATH-???")
            nodes      = path.get("nodes", [])

            # ── Deduplication gate ────────────────────────────────────────
            existing = self._already_certified(finding_id)
            if existing:
                print(f"[DEDUP] ⟳ {finding_id} — already certified in block "
                      f"{existing['block']} on {existing['timestamp'][:10]}")
                print(f"[DEDUP]   Hash: {existing['hash']}...")
                print(f"[DEDUP]   Skipping — chain record is permanent proof.")
                print()
                self.results["deduplicated"].append({
                    "finding_id": finding_id,
                    "block"     : existing["block"],
                    "hash"      : existing["hash"],
                    "certified_at": existing["timestamp"]
                })
                continue   # ← never reaches Trinity for this finding

            # ── New finding — run through Trinity ─────────────────────────
            steps   = self._extract_steps(nodes)
            score   = self._compute_score(path, nodes)
            stealth = self._compute_stealth(nodes)
            novelty = self._compute_novelty(nodes)

            block = self.bridge.phantom_submit(
                finding_id=finding_id,
                steps=steps, score=score,
                stealth=stealth, novelty=novelty
            )

            if block:
                self.results["certified"].append({
                    "finding_id": finding_id,
                    "block"     : block.index,
                    "hash"      : block.hash[:24],
                    "score"     : score
                })
            else:
                self.results["blocked"].append(
                    {"finding_id": finding_id, "score": score}
                )

        self._final_report()
        return self.results

    def _final_report(self):
        print("═" * 60)
        print("MISTCODER BLOCKCHAIN — REAL SCAN RESULTS")
        print("═" * 60)
        print(f"Scan ID  : {self.results['scan_id']}")
        print()

        certified   = self.results["certified"]
        blocked     = self.results["blocked"]
        deduped     = self.results["deduplicated"]

        if certified:
            print(f"✓ CERTIFIED ({len(certified)} new kill chains added to chain):")
            for r in certified:
                print(f"  Block {r['block']} | {r['finding_id']} | "
                      f"score={r['score']} | {r['hash']}...")
            print()

        if blocked:
            print(f"✗ BLOCKED ({len(blocked)} kill chains rejected by COVENANT):")
            for r in blocked:
                print(f"  {r['finding_id']} | score={r['score']}")
            print()

        if deduped:
            print(f"⟳ DEDUPLICATED ({len(deduped)} already certified — skipped):")
            for r in deduped:
                print(f"  {r['finding_id']} → block {r['block']} "
                      f"certified {r['certified_at'][:10]}")
            print()

        if not certified and not blocked:
            print("  No new findings this scan — chain unchanged.")
            print()

        self.bridge.report()

        # Save chain only if new blocks were added
        if certified:
            MistChainPersistence.save(self.bridge.chain)
            print(f"[PERSIST] Ledger updated: {MistChainPersistence.stats()}")
        else:
            print("[PERSIST] Chain unchanged — no save needed.")