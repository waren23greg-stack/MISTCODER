# MISTCODER

**Multi-layer Intelligent Static/Dynamic Code Reasoning Engine**

[![CI](https://github.com/waren23greg-stack/MISTCODER/actions/workflows/ci.yml/badge.svg)](https://github.com/waren23greg-stack/MISTCODER/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)](https://python.org)
[![Phase](https://img.shields.io/badge/Phase-4%20Reasoning%20Engine-8848c0?style=flat-square)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Engines](https://img.shields.io/badge/Engines-9%2F9-brightgreen?style=flat-square)](#architecture)

> *A self-improving, reasoning-first vulnerability intelligence system. It doesn't just find bugs — it understands why they're exploitable, ranks them by real-world risk, and signs every conclusion with a cryptographic audit trail.*

---

## Quickstart

```bash
git clone https://github.com/waren23greg-stack/MISTCODER.git
cd MISTCODER

# Full scan with attack path analysis and compliance export
python mistcoder.py scan src/ --phantom

# Audit trail status
python mistcoder.py covenant status

# Check all 9 engines are ready
python mistcoder.py status
```

---

## Architecture

```
INPUT (any target)
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│  LAYER 1 — INGESTION                                    │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌───────┐  │
│  │  ORACLE  │  │  PARSER  │  │URL_SCANNER│  │BIN_LFT│  │
│  │ Python   │  │ Multi-   │  │ HTTP deep │  │x86_64 │  │
│  │ taint    │  │ language │  │ scan +    │  │disasm │  │
│  │ analysis │  │ AST→IR   │  │ JS extract│  │callgrp│  │
│  └────┬─────┘  └────┬─────┘  └─────┬─────┘  └───┬───┘  │
└───────┼─────────────┼──────────────┼─────────────┼──────┘
        └─────────────┴──────────────┴─────────────┘
                              │
                              ▼
               ┌──────────────────────────┐
               │  LAYER 2 — IR BRIDGE     │
               │  Normalise all findings  │
               │  into UnifiedIR format   │
               └──────────────┬───────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────┐
│  LAYER 3 — KNOWLEDGE GRAPH                              │
│  ┌────────────────────┐  ┌──────────────────────────┐   │
│  │  PHANTOM / TKG     │  │  ATTACK PATH FINDER      │   │
│  │  Builds Threat     │  │  DFS over TKG → exploit  │   │
│  │  Knowledge Graph   │  │  chains ranked by CVSS   │   │
│  └────────────┬───────┘  └──────────────┬───────────┘   │
└───────────────┼─────────────────────────┼───────────────┘
                └─────────────┬───────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────┐
│  LAYER 4 — REASONING                                    │
│  ┌──────────────────┐  ┌──────────────────────────┐     │
│  │ ATTACK PATH      │  │  EXPLAINABILITY CHAINS   │     │
│  │ REASONER         │  │  Human-readable output   │     │
│  │ Adversarial      │  │  per attack path         │     │
│  │ scoring          │  └──────────────────────────┘     │
│  └──────────────────┘                                   │
│  ┌──────────────────┐                                   │
│  │ VULN DISCOVERY   │                                   │
│  │ Emergent pattern │                                   │
│  │ inference        │                                   │
│  └──────────────────┘                                   │
└─────────────────────────────────────────────────────────┘
                              │
                              ▼
               ┌──────────────────────────┐
               │  COVENANT AUDIT ENGINE   │
               │  SHA-256 hash chain      │
               │  CVSS + OWASP mapping    │
               │  JSON / CSV / MD export  │
               │  Kill switch             │
               └──────────────────────────┘
```

---

## Engine Map

| Layer | Engine | File | Status |
|-------|--------|------|--------|
| Ingestion | ORACLE | `modules/ingestion/src/python_ast_walker.py` | ✅ |
| Ingestion | PARSER | `modules/ingestion/src/parser.py` | ✅ |
| Ingestion | URL_SCANNER | `modules/ingestion/src/url_scanner.py` | ✅ |
| Ingestion | BINARY_LIFT | `modules/binary_lifting/src/` | ✅ |
| Bridge | IR_BRIDGE | `modules/ingestion/src/ir_bridge.py` | ✅ |
| Knowledge | TKG / PHANTOM | `modules/knowledge_graph/src/phantom.py` | ✅ |
| Knowledge | ATTACK_FINDER | `modules/knowledge_graph/src/attack_path_finder.py` | ✅ |
| Reasoning | REASONER | `modules/reasoning/src/attack_path_reasoning.py` | ✅ |
| Reasoning | EXPLAINABILITY | `modules/reasoning/src/explainability_chains.py` | ✅ |
| Oversight | COVENANT | `modules/oversight/src/covenant.py` | ✅ |

---

## CLI Reference

```bash
# Engine status
python mistcoder.py status

# Self-test all engines
python mistcoder.py selftest

# Scan a directory (Python + JS + binaries)
python mistcoder.py scan <path>

# Scan with full attack path analysis
python mistcoder.py scan <path> --phantom

# Scan and export JSON report
python mistcoder.py scan <path> --phantom --json sandbox/report.json

# Scan a URL
python mistcoder.py scan https://target.example.com

# Audit trail
python mistcoder.py covenant status
python mistcoder.py covenant verify
python mistcoder.py covenant export sandbox/report.json sandbox/compliance

# Individual engines
python oracle.py --self-test
python oracle.py src/auth.py --json
python modules/oversight/src/covenant.py selftest
python modules/knowledge_graph/src/phantom.py
```

---

## Findings & Compliance

Every scan automatically produces:

- **Terminal report** — colour-coded findings with CWE IDs and remediation
- **Ranked attack paths** — exploit chains scored by CVSS v3.1
- **Compliance JSON** — machine-readable with OWASP Top 10 2021 mapping
- **Compliance Markdown** — human-readable report for review
- **Audit chain record** — SHA-256 hash-chained, tamper-evident

```
sandbox/
  audit_chain.json          ← hash-chained record of every scan
  MSTC-<id>_compliance.json ← full compliance report
  MSTC-<id>_compliance.md   ← markdown report
```

---

## Module Specs

| Spec | Module | File |
|------|--------|------|
| MOD-01 | Ingestion Engine (UCIE) | `SPEC2.md` |
| MOD-02 | Static Deep Analysis | `specs/MOD-02-SDAE.md` |
| MOD-03 | Dynamic Behavioural Analysis | `specs/MOD-03-DBAE.md` |
| MOD-04 | Reasoning Core | `SPEC.md` |
| MOD-05 | Offensive Simulation | `specs/MOD-05-OFFSIM.md` |
| MOD-06 | Self-Improvement Loop | `specs/MOD-06-SELF.md` |
| MOD-07 | Oversight & Governance | `specs/MOD-07-OVERSIGHT.md` |

---

## Build Progress

| Step | Module | Commit |
|------|--------|--------|
| ✅ Step 1 | ORACLE — Python AST taint engine | `feat(oracle)` |
| ✅ Step 2 | NEXUS — Unified CLI + IR bridge | `feat(nexus)` |
| ✅ Step 3 | PHANTOM — TKG + attack path reasoning | `feat(phantom)` |
| ✅ Step 4 | COVENANT — Cryptographic audit engine | `feat(covenant)` |
| ✅ Step 5 | RELEASE — Package structure + CI + merge | `feat(release)` |

---

## Ethics & Scope

MISTCODER is a **white-hat, defensive security tool** built for authorised security assessment, vulnerability research, and compliance reporting. See [ETHICS.md](ETHICS.md) and [SECURITY.md](SECURITY.md).

**Never run MISTCODER against systems you do not own or have explicit written authorisation to test.**
