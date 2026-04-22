# COVENANT REPORT — MSTC-20260422-093434-E05D7E
**Generated:** 2026-04-22T07:18:30 UTC  |  **Chain Entry:** 1  |  **Valid:** True

## Risk Trend: BASELINE

## Findings
| Severity | Count |
|---|---|
| CRITICAL | 5 |
| HIGH | 41 |
| MEDIUM | 6 |
| LOW | 13 |

## Attack Chains
Total: 14

### Chain 01  (score 7.38)
- Steps: 2  P(success): 0.8

### Chain 02  (score 7.38)
- Steps: 2  P(success): 0.8

### Chain 03  (score 7.38)
- Steps: 2  P(success): 0.8

### Chain 04  (score 7.38)
- Steps: 2  P(success): 0.8

### Chain 05  (score 7.38)
- Steps: 2  P(success): 0.8

## OWASP Top 10 Coverage
- **A01:Broken Access Control**: 30 findings
- **A03:Injection**: 19 findings
- **A02:Cryptographic Failures**: 3 findings

## Remediation Roadmap
- [LOW] **CWE-327** (3x): Replace MD5/SHA1/DES with SHA-256+ or AES-256
- [LOW] **CWE-89** (6x): Parameterize all SQL queries — use ORM or prepared statements
- [LOW] **CWE-22** (30x): Validate and canonicalize all file paths — use Path.resolve()
- [MEDIUM] **CWE-312** (13x): Review all CWE-312 occurrences
- [HIGH] **CWE-94** (13x): Remove eval/exec on untrusted input — use AST-safe parsers