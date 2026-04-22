# MISTCODER
### Adversarial Intelligence Platform · Phase IV Reasoning Engine

```
  ███╗   ███╗██╗███████╗████████╗ ██████╗ ██████╗ ██████╗ ███████╗██████╗
  ████╗ ████║██║██╔════╝╚══██╔══╝██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗
  ██╔████╔██║██║███████╗   ██║   ██║     ██║   ██║██║  ██║█████╗  ██████╔╝
  ██║╚██╔╝██║██║╚════██║   ██║   ██║     ██║   ██║██║  ██║██╔══╝  ██╔══██╗
  ██║ ╚═╝ ██║██║███████║   ██║   ╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║
  ╚═╝     ╚═╝╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
```

> **AI-powered static analysis that builds a Threat Knowledge Graph, enumerates ranked attack chains, and signs every scan to an immutable audit ledger — all from a single Python command, zero external dependencies.**

---

## The Problem

Most codebases ship with vulnerabilities nobody found because:
- Manual review doesn't scale
- Generic linters find bugs, not *attack paths*
- There's no tamper-evident record that a scan even happened

**MISTCODER** solves all three.

---

## What It Does

```
python mistcoder.py scan modules/
         │
         ▼
  ┌─────────────────────────────────────────────────────────┐
  │  ORACLE  ─  AST taint-flow engine                       │
  │    65 findings across 24 files in 38ms                  │
  │    SQL injection · Path traversal · Code execution      │
  ├─────────────────────────────────────────────────────────┤
  │  PHANTOM ─  Threat Knowledge Graph                      │
  │    65 nodes · 41 edges · 14 ranked attack chains        │
  │    CHAIN-01 score=8.31 eval_exec→eval_exec→Password     │
  ├─────────────────────────────────────────────────────────┤
  │  COVENANT ─  Immutable Intelligence Ledger              │
  │    Hash-chained · MITRE ATT&CK · OWASP Top 10           │
  │    entry 2 of 2 · ⬡ CHAIN INTACT                       │
  └─────────────────────────────────────────────────────────┘
```

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                        MISTCODER                               │
│                                                                │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐ │
│  │  ORACLE  │───▶│  NEXUS   │───▶│ PHANTOM  │───▶│COVENANT  │ │
│  │  AST     │    │  Unified │    │  TKG +   │    │  Ledger  │ │
│  │  Taint   │    │  CLI/IR  │    │  Paths   │    │  Chain   │ │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘ │
│       │                               │                │       │
│  Python AST              AttackPathFinder         SHA-256     │
│  CWE mapping             65 nodes/41 edges        MITRE TTP   │
│  CVSS scoring            14 kill chains           OWASP map   │
└────────────────────────────────────────────────────────────────┘
```

| Module | Role | Status |
|--------|------|--------|
| **ORACLE** | Python AST taint-flow analysis engine | ✅ Live |
| **NEXUS** | Unified CLI bridge, IR normalization | ✅ Live |
| **PHANTOM** | Threat Knowledge Graph + Attack Path Finder | ✅ Live |
| **COVENANT** | Immutable hash-chained audit ledger | ✅ Live |

---

## Real Output — 38ms

```
════════════════════════════════════════════════════════════════
  COVENANT INTELLIGENCE REPORT
════════════════════════════════════════════════════════════════
  Ledger    : entry 2 of 2  │  ⬡ CHAIN INTACT
  Risk Trend: STABLE

  ATTACK CHAINS  (14 ranked)

  CHAIN-01  score=8.31  steps=3  p(success)=0.64
      ◈   [CRITICAL] eval_exec  test_gaps.py:105  CWE-94
      └─▶ [CRITICAL] eval_exec  test_gaps.py:118  CWE-94
      └─▶ [HIGH] Password  test_gaps.py:25  CWE-312

  CHAIN-06  score=7.76  steps=4  p(success)=0.512
      ◈   [CRITICAL] eval_exec  test_parser.py:257  CWE-94
      └─▶ [HIGH] file_path  test_parser.py:344  CWE-22
      └─▶ [HIGH] file_path  test_parser.py:362  CWE-22
      └─▶ [HIGH] Password  test_parser.py:157  CWE-312

  COMPLIANCE MATRIX
  A01: Broken Access Control  ████████████████████ 30 findings
  A03: Injection              ████████████████████ 19 findings

  ⬛ CRITICAL RISK — Halt deployments. Patch immediately.
════════════════════════════════════════════════════════════════
  PHANTOM BRIDGE complete  │  findings: 65  paths: 14  time: 38ms
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/waren23greg-stack/MISTCODER.git
cd MISTCODER

# Scan your codebase
python mistcoder.py scan path/to/code/

# Full intelligence pipeline
python phantom_bridge.py sandbox/unified_ir.json

# Signed audit report
python covenant_engine.py sandbox/phantom_report.json
```

**Zero dependencies. Python 3.8+. Runs anywhere.**

---

## What Makes MISTCODER Different

| Feature | Traditional SAST | MISTCODER |
|---------|-----------------|-----------|
| Analysis | Rule-based pattern matching | AST taint-flow (data follows paths) |
| Output | List of findings | **Ranked attack kill chains** |
| Graph | ❌ | **Threat Knowledge Graph** (65 nodes, 41 edges) |
| Audit | ❌ | **Hash-chained immutable ledger** |
| Compliance | Manual | Auto-mapped to **MITRE ATT&CK + OWASP** |
| Dependencies | Many | **Zero** |
| Speed | Minutes | **38ms** |

---

## COVENANT — The Chain of Truth

Every scan is cryptographically linked to the previous. Tamper one entry — the chain breaks.

```
2026-04-22T07:18:30  49eb226accfe3f1e…  findings=65  paths=14
        │
        └──SHA-256──▶
2026-04-22T07:24:17  ecdaf9baeff77771…  findings=65  paths=14

Chain status: VERIFIED — 2 entries intact
Risk Trend  : STABLE
```

This isn't just a report. It's a **cryptographic proof** your codebase was audited.

---

## Roadmap

- [ ] **CI/CD Integration** — GitHub Actions, GitLab CI one-liner
- [ ] **VS Code Extension** — inline vulnerability highlighting
- [ ] **API Mode** — REST endpoint for pipeline integration
- [ ] **Multi-language** — JavaScript, Go, Java AST engines
- [ ] **Dashboard** — Real-time web UI with live chain visualization
- [ ] **CVE Correlation** — Auto-match findings to NVD CVE database

---

## Why This Matters

Security vulnerabilities cost organizations an average of **$4.45M per breach** (IBM 2023). Most are preventable. MISTCODER finds the *paths an attacker would take* — not just individual bugs — giving developers exactly what to fix first.

Built by a developer, for developers. Free. Open. Fast.

---

## Project Structure

```
MISTCODER/
├── mistcoder.py                  # Unified CLI entry point
├── phantom_bridge.py             # Full intelligence pipeline
├── covenant_engine.py            # Immutable audit ledger
├── modules/
│   ├── analysis/src/             # AST taint-flow engine (ORACLE)
│   ├── knowledge_graph/src/      # TKG + AttackPathFinder (PHANTOM)
│   ├── reasoning/src/            # Attack path reasoning engine
│   └── oversight/src/            # CVSS scoring + compliance
└── sandbox/
    ├── unified_ir.json           # Intermediate representation
    ├── phantom_report.json       # Full intelligence report
    ├── covenant_report.json      # Compliance + remediation
    └── covenant_ledger.json      # Immutable hash-chained ledger
```

---

<div align="center">

**Built with zero external dependencies · Python 3.8+ · 38ms full pipeline**

*MISTCODER — Know your attack surface before the adversary does.*

</div>
