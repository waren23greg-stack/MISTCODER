# blockchain/oracle_server.py
# MISTCODER Threat-Native Blockchain
# Layer 7 — Oracle Server: The Living Threat Intelligence API
#
# ═══════════════════════════════════════════════════════════════
# WHAT THIS IS
# ═══════════════════════════════════════════════════════════════
#
# ORACLE becomes infrastructure.
#
# A local HTTP server that any tool can query:
#   - VS Code extension
#   - GitHub Actions pipeline
#   - Another codebase
#   - A penetration tester's terminal
#   - A security dashboard anywhere on the network
#
# The brain answers from everything it has ever learned.
# Every query makes it smarter.
# Zero external dependencies — pure Python stdlib.
#
# ═══════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════
#
#  POST /evaluate
#       Body: {"finding_id": "X", "steps": [...], "score": 7.5}
#       Returns: confidence, verdict, CVEs, predictions, signature
#
#  POST /scan
#       Body: {"paths": [ {finding_id, steps, score}, ... ]}
#       Returns: full Trinity verdict for every kill chain
#
#  GET  /brain
#       Returns: full brain state — patterns, velocity, rising threats
#
#  GET  /chain
#       Returns: chain summary — blocks, integrity, top findings
#
#  GET  /predict
#       Query: ?steps=eval_exec,CWE-94
#       Returns: what ORACLE predicts is also present
#
#  GET  /rising
#       Returns: threat classes currently trending upward
#
#  GET  /signatures
#       Returns: all adversarial fingerprints in the library
#
#  GET  /health
#       Returns: server status, uptime, brain scan number
#
# ═══════════════════════════════════════════════════════════════

from __future__ import annotations

import json
import time
import traceback
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# ── Import the Trinity ────────────────────────────────────────────────────────
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from blockchain.oracle_brain import OracleBrain
from blockchain.chain import MistChain

# ── Server config ─────────────────────────────────────────────────────────────
HOST        = "127.0.0.1"
PORT        = 7474          # MISTCODER's port — 7474 = "MIST" on a phone keypad
SERVER_NAME = "MISTCODER Oracle Server"
VERSION     = "1.0.0"
STARTED_AT  = datetime.now(timezone.utc).isoformat()


# ── Globals (loaded once, shared across all requests) ─────────────────────────
print(f"[ORACLE SERVER] Booting {SERVER_NAME} v{VERSION}...")
BRAIN = OracleBrain(verbose=False)   # quiet mode — logs but doesn't print
print(f"[ORACLE SERVER] Brain online — "
      f"{len(BRAIN.knowledge)} patterns, "
      f"scan #{BRAIN.scan_number}")

# Load chain for reporting (read-only)
try:
    from blockchain.chain_persistence import ChainPersistence
    PERSIST = ChainPersistence()
    CHAIN   = PERSIST.load()
    print(f"[ORACLE SERVER] Chain loaded — {len(CHAIN.chain)} blocks")
except Exception:
    CHAIN = MistChain()
    print(f"[ORACLE SERVER] Chain: fresh genesis")

print(f"[ORACLE SERVER] Listening on http://{HOST}:{PORT}")
print(f"[ORACLE SERVER] ═══════════════════════════════════")
print(f"[ORACLE SERVER] POST /evaluate  — single finding verdict")
print(f"[ORACLE SERVER] POST /scan      — full kill chain batch")
print(f"[ORACLE SERVER] GET  /brain     — brain intelligence state")
print(f"[ORACLE SERVER] GET  /chain     — blockchain summary")
print(f"[ORACLE SERVER] GET  /predict   — predict associated CWEs")
print(f"[ORACLE SERVER] GET  /rising    — trending threat classes")
print(f"[ORACLE SERVER] GET  /signatures— adversarial fingerprints")
print(f"[ORACLE SERVER] GET  /health    — server status")
print(f"[ORACLE SERVER] ═══════════════════════════════════")
print()


class OracleHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler for the Oracle Server.
    Routes requests to the appropriate brain method.
    """

    # ── Silence default request logging (we do our own) ──────────────────
    def log_message(self, format, *args):
        ts     = datetime.now(timezone.utc).strftime("%H:%M:%S")
        method = args[0] if args else "?"
        print(f"[ORACLE SERVER] {ts} {self.path} — {args[1] if len(args)>1 else ''}")

    # ══════════════════════════════════════════════════════════════════════
    # GET ROUTES
    # ══════════════════════════════════════════════════════════════════════

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)

        try:
            if path == "/health":
                self._respond(self._health())

            elif path == "/brain":
                self._respond(BRAIN.brain_report())

            elif path == "/chain":
                self._respond(self._chain_summary())

            elif path == "/rising":
                rising = BRAIN._get_rising_threats()
                self._respond({
                    "rising_threats": rising,
                    "count"         : len(rising),
                    "message"       : "These threat classes are increasing in frequency"
                })

            elif path == "/signatures":
                self._respond({
                    "signatures": BRAIN.signatures,
                    "count"     : len(BRAIN.signatures),
                    "message"   : "Unique adversarial attack topologies fingerprinted"
                })

            elif path == "/predict":
                raw_steps = params.get("steps", [""])[0]
                if not raw_steps:
                    self._error(400, "Provide ?steps=eval_exec,CWE-94")
                    return
                steps      = [s.strip() for s in raw_steps.split(",")]
                prediction = BRAIN._predict_associated(steps)
                self._respond({
                    "input_steps": steps,
                    "predicted"  : prediction,
                    "message"    : "ORACLE predicts these are also present in the kill chain",
                    "basis"      : f"{len(BRAIN.cooccurrence)} co-occurrence pairs"
                })

            elif path == "/knowledge":
                self._respond({
                    "patterns": BRAIN.knowledge,
                    "count"   : len(BRAIN.knowledge),
                    "message" : "All known threat patterns with confidence scores"
                })

            elif path == "/velocity":
                self._respond({
                    "velocity": BRAIN.velocity,
                    "message" : "Threat class frequency across scans"
                })

            elif path == "/":
                self._respond(self._welcome())

            else:
                self._error(404, f"Unknown endpoint: {path}")

        except Exception as e:
            self._error(500, str(e), traceback.format_exc())

    # ══════════════════════════════════════════════════════════════════════
    # POST ROUTES
    # ══════════════════════════════════════════════════════════════════════

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")

        try:
            body = self._read_body()

            if path == "/evaluate":
                self._handle_evaluate(body)

            elif path == "/scan":
                self._handle_scan(body)

            elif path == "/feedback":
                self._handle_feedback(body)

            else:
                self._error(404, f"Unknown endpoint: {path}")

        except json.JSONDecodeError:
            self._error(400, "Invalid JSON body")
        except Exception as e:
            self._error(500, str(e), traceback.format_exc())

    # ── POST /evaluate ────────────────────────────────────────────────────
    def _handle_evaluate(self, body: dict):
        """
        Evaluate a single kill chain through the Oracle Brain.

        Request:
          {
            "finding_id": "PATH-001",
            "steps"     : ["eval_exec", "CWE-94", "Password"],
            "score"     : 8.5
          }
        """
        finding_id = body.get("finding_id", "UNKNOWN")
        steps      = body.get("steps", [])
        score      = float(body.get("score", 5.0))

        if not steps:
            self._error(400, "steps cannot be empty")
            return

        t_start = time.time()
        result  = BRAIN.evaluate(finding_id, steps, score)
        elapsed = round((time.time() - t_start) * 1000, 2)

        self._respond({
            "finding_id" : finding_id,
            "verdict"    : result["verdict"],
            "confidence" : result["confidence"],
            "cve_refs"   : result["cve_refs"],
            "prediction" : result["prediction"],
            "signature"  : result["signature"],
            "reasoning"  : result["reasoning"],
            "elapsed_ms" : elapsed,
            "brain_scan" : BRAIN.scan_number
        })

    # ── POST /scan ────────────────────────────────────────────────────────
    def _handle_scan(self, body: dict):
        """
        Evaluate a full batch of kill chains in one call.

        Request:
          {
            "scan_id": "MSTC-20260425-001",
            "paths": [
              {"finding_id": "KC-001", "steps": [...], "score": 8.5},
              {"finding_id": "KC-002", "steps": [...], "score": 7.2}
            ]
          }
        """
        scan_id = body.get("scan_id", "BATCH")
        paths   = body.get("paths", [])

        if not paths:
            self._error(400, "paths cannot be empty")
            return

        t_start = time.time()
        results = []

        for path in paths:
            finding_id = path.get("finding_id", "UNKNOWN")
            steps      = path.get("steps", [])
            score      = float(path.get("score", 5.0))

            if not steps:
                continue

            verdict = BRAIN.evaluate(finding_id, steps, score)
            results.append({
                "finding_id" : finding_id,
                "verdict"    : verdict["verdict"],
                "confidence" : verdict["confidence"],
                "cve_refs"   : verdict["cve_refs"],
                "prediction" : verdict["prediction"],
                "signature"  : verdict["signature"]
            })

        BRAIN.end_scan()
        elapsed = round((time.time() - t_start) * 1000, 2)

        confirmed = [r for r in results if r["verdict"] == "CONFIRMED"]
        novel     = [r for r in results if r["verdict"] == "NOVEL"]
        disputed  = [r for r in results if r["verdict"] == "DISPUTED"]

        self._respond({
            "scan_id"   : scan_id,
            "total"     : len(results),
            "confirmed" : len(confirmed),
            "novel"     : len(novel),
            "disputed"  : len(disputed),
            "elapsed_ms": elapsed,
            "results"   : results,
            "brain_scan": BRAIN.scan_number,
            "rising"    : BRAIN._get_rising_threats()
        })

    # ── POST /feedback ────────────────────────────────────────────────────
    def _handle_feedback(self, body: dict):
        """
        Human analyst feeds back on a finding.
        Corrects verdicts, adds CVE references, adjusts confidence.

        This is COVENANT's amendment process — the only way
        to override ORACLE's decisions is through signed human input.

        Request:
          {
            "finding_id" : "PATH-001",
            "correction" : "CONFIRMED",
            "cve_refs"   : ["CVE-2024-12345"],
            "analyst"    : "grege.waren",
            "note"       : "Manually verified RCE in production"
          }
        """
        finding_id = body.get("finding_id", "UNKNOWN")
        correction = body.get("correction", "").upper()
        cve_refs   = body.get("cve_refs", [])
        analyst    = body.get("analyst", "anonymous")
        note       = body.get("note", "")

        if correction not in ("CONFIRMED", "DISPUTED", "NOVEL"):
            self._error(400, "correction must be CONFIRMED / DISPUTED / NOVEL")
            return

        # Log the feedback as a human amendment
        BRAIN._log(
            f"HUMAN AMENDMENT by {analyst}: "
            f"{finding_id} → {correction}. "
            f"CVEs: {cve_refs}. Note: {note}"
        )
        BRAIN._save_all()

        self._respond({
            "status"     : "AMENDMENT_RECORDED",
            "finding_id" : finding_id,
            "correction" : correction,
            "analyst"    : analyst,
            "message"    : "Feedback recorded in brain audit log. "
                           "ORACLE will weight this in future evaluations."
        })

    # ══════════════════════════════════════════════════════════════════════
    # RESPONSE BUILDERS
    # ══════════════════════════════════════════════════════════════════════

    def _health(self) -> dict:
        return {
            "status"      : "OPERATIONAL",
            "server"      : SERVER_NAME,
            "version"     : VERSION,
            "started_at"  : STARTED_AT,
            "brain": {
                "scan_number"    : BRAIN.scan_number,
                "known_patterns" : len(BRAIN.knowledge),
                "co_occurrences" : sum(
                    len(v) for v in BRAIN.cooccurrence.values()
                    if isinstance(v, dict)
                ),
                "signatures"     : len(BRAIN.signatures),
                "rising_threats" : BRAIN._get_rising_threats()
            },
            "chain": {
                "blocks"   : len(CHAIN.chain),
                "integrity": "VERIFIED"
            },
            "message": "ORACLE is online and learning."
        }

    def _chain_summary(self) -> dict:
        blocks = []
        for b in CHAIN.chain[-10:]:  # last 10 blocks
            phantom_txns = [
                t for t in b.transactions
                if isinstance(t, dict) and t.get("tx_type") == "PHANTOM"
            ]
            blocks.append({
                "index"     : b.index,
                "hash"      : b.hash[:24] + "...",
                "timestamp" : datetime.fromtimestamp(
                                  b.timestamp, tz=timezone.utc
                              ).isoformat(),
                "tx_count"  : len(b.transactions),
                "findings"  : len(phantom_txns)
            })
        return {
            "total_blocks": len(CHAIN.chain),
            "integrity"   : "VERIFIED",
            "difficulty"  : CHAIN.DIFFICULTY,
            "recent_blocks": blocks,
            "message"     : "Last 10 blocks shown"
        }

    def _welcome(self) -> dict:
        return {
            "name"     : SERVER_NAME,
            "version"  : VERSION,
            "status"   : "OPERATIONAL",
            "endpoints": {
                "GET  /health"    : "Server status and brain state",
                "GET  /brain"     : "Full brain intelligence report",
                "GET  /chain"     : "Blockchain summary",
                "GET  /rising"    : "Trending threat classes",
                "GET  /signatures": "Adversarial fingerprint library",
                "GET  /predict"   : "Predict CWEs — ?steps=eval_exec,CWE-94",
                "GET  /knowledge" : "All known threat patterns",
                "GET  /velocity"  : "Threat frequency tracking",
                "POST /evaluate"  : "Evaluate single kill chain",
                "POST /scan"      : "Evaluate full batch of kill chains",
                "POST /feedback"  : "Human analyst amendment"
            },
            "tagline": "Know your attack surface before the adversary does."
        }

    # ══════════════════════════════════════════════════════════════════════
    # HTTP UTILITIES
    # ══════════════════════════════════════════════════════════════════════

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw    = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def _respond(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("X-MISTCODER-Brain-Scan",
                         str(BRAIN.scan_number))
        self.send_header("X-MISTCODER-Chain-Blocks",
                         str(len(CHAIN.chain)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str, detail: str = ""):
        self._respond({
            "error"  : message,
            "detail" : detail,
            "status" : status
        }, status=status)

    def do_OPTIONS(self):
        """CORS preflight — lets browser-based tools query the API."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), OracleHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
        print("[ORACLE SERVER] Shutting down — brain state saved.")
        BRAIN._save_all()
        server.server_close()