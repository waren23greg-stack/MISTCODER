# MISTCODER Compliance Report

| Field | Value |
|-------|-------|
| Report ID | `0f4c747c-dd57-4870-8143-a34347e695ae` |
| Scan ID | `MSTC-20260422-102206-E05D7E` |
| Target | `modules/` |
| Generated | 2026-04-22T07:22:07.308406Z |
| **Risk Rating** | **CRITICAL** |
| Top CVSS | 9.1 |

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 5 |
| HIGH     | 41 |
| MEDIUM   | 6 |
| LOW      | 13 |
| INFO     | 0 |

## OWASP Top 10 Coverage

- **A01:2021 — Broken Access Control**: 30 finding(s)
- **A03:2021 — Injection**: 19 finding(s)
- **Uncategorised**: 13 finding(s)
- **A02:2021 — Cryptographic Failures**: 3 finding(s)

## Findings

### HIGH — deserialization → sql_query
- **CVSS**: 7.5  |  **CWE**: CWE-89  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\analysis\src\analysis_engine.py:0`
- **Fix**: See OWASP guidance.

### HIGH — deserialization → sql_query
- **CVSS**: 7.5  |  **CWE**: CWE-89  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\analysis\src\analysis_engine.py:0`
- **Fix**: See OWASP guidance.

### HIGH — deserialization → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\analysis\src\analysis_engine.py:0`
- **Fix**: See OWASP guidance.

### HIGH — cli_arg → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\analysis\src\analysis_engine.py:0`
- **Fix**: See OWASP guidance.

### HIGH — env_var → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\analysis\src\analyzer.py:0`
- **Fix**: See OWASP guidance.

### LOW — env_var → file_path
- **CVSS**: 3.1  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\analysis\src\analyzer.py:0`
- **Fix**: See OWASP guidance.

### HIGH — Weak Cipher
- **CVSS**: 7.5  |  **CWE**: CWE-327  |  **OWASP**: A02:2021 — Cryptographic Failures
- **Location**: `modules\binary_lifting\src\disasm_x86_64.py:0`
- **Fix**: See OWASP guidance.

### HIGH — deserialization → sql_query
- **CVSS**: 7.5  |  **CWE**: CWE-89  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\ingestion\src\oracle_report.py:0`
- **Fix**: See OWASP guidance.

### HIGH — env_var → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\ingestion\src\oracle_report.py:0`
- **Fix**: See OWASP guidance.

### HIGH — env_var → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\ingestion\src\oracle_report.py:0`
- **Fix**: See OWASP guidance.

### CRITICAL — deserialization → eval_exec
- **CVSS**: 9.1  |  **CWE**: CWE-94  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\ingestion\src\parser.py:0`
- **Fix**: See OWASP guidance.

### CRITICAL — deserialization → eval_exec
- **CVSS**: 9.1  |  **CWE**: CWE-94  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\ingestion\src\parser.py:0`
- **Fix**: See OWASP guidance.

### LOW — deserialization → eval_exec
- **CVSS**: 3.1  |  **CWE**: CWE-94  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\ingestion\src\parser.py:0`
- **Fix**: See OWASP guidance.

### LOW — deserialization → eval_exec
- **CVSS**: 3.1  |  **CWE**: CWE-94  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\ingestion\src\parser.py:0`
- **Fix**: See OWASP guidance.

### LOW — deserialization → eval_exec
- **CVSS**: 3.1  |  **CWE**: CWE-94  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\ingestion\src\parser.py:0`
- **Fix**: See OWASP guidance.

### LOW — deserialization → eval_exec
- **CVSS**: 3.1  |  **CWE**: CWE-94  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\ingestion\src\parser.py:0`
- **Fix**: See OWASP guidance.

### LOW — deserialization → eval_exec
- **CVSS**: 3.1  |  **CWE**: CWE-94  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\ingestion\src\parser.py:0`
- **Fix**: See OWASP guidance.

### LOW — deserialization → eval_exec
- **CVSS**: 3.1  |  **CWE**: CWE-94  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\ingestion\src\parser.py:0`
- **Fix**: See OWASP guidance.

### LOW — deserialization → eval_exec
- **CVSS**: 3.1  |  **CWE**: CWE-94  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\ingestion\src\parser.py:0`
- **Fix**: See OWASP guidance.

### LOW — deserialization → eval_exec
- **CVSS**: 3.1  |  **CWE**: CWE-94  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\ingestion\src\parser.py:0`
- **Fix**: See OWASP guidance.

### LOW — deserialization → file_path
- **CVSS**: 3.1  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\ingestion\src\parser.py:0`
- **Fix**: See OWASP guidance.

### LOW — deserialization → file_path
- **CVSS**: 3.1  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\ingestion\src\parser.py:0`
- **Fix**: See OWASP guidance.

### HIGH — Password
- **CVSS**: 7.5  |  **CWE**: CWE-312  |  **OWASP**: Uncategorised
- **Location**: `modules\ingestion\src\taint_model.py:0`
- **Fix**: See OWASP guidance.

### CRITICAL — http_param → eval_exec
- **CVSS**: 9.1  |  **CWE**: CWE-94  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\ingestion\tests\test_gaps.py:0`
- **Fix**: See OWASP guidance.

### CRITICAL — cli_arg → eval_exec
- **CVSS**: 9.1  |  **CWE**: CWE-94  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\ingestion\tests\test_gaps.py:0`
- **Fix**: See OWASP guidance.

### HIGH — Password
- **CVSS**: 7.5  |  **CWE**: CWE-312  |  **OWASP**: Uncategorised
- **Location**: `modules\ingestion\tests\test_gaps.py:0`
- **Fix**: See OWASP guidance.

### CRITICAL — env_var → eval_exec
- **CVSS**: 9.1  |  **CWE**: CWE-94  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\ingestion\tests\test_parser.py:0`
- **Fix**: See OWASP guidance.

### HIGH — env_var → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\ingestion\tests\test_parser.py:0`
- **Fix**: See OWASP guidance.

### HIGH — env_var → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\ingestion\tests\test_parser.py:0`
- **Fix**: See OWASP guidance.

### HIGH — Password
- **CVSS**: 7.5  |  **CWE**: CWE-312  |  **OWASP**: Uncategorised
- **Location**: `modules\ingestion\tests\test_parser.py:0`
- **Fix**: See OWASP guidance.

### HIGH — Password
- **CVSS**: 7.5  |  **CWE**: CWE-312  |  **OWASP**: Uncategorised
- **Location**: `modules\knowledge_graph\src\neo4j_backend.py:0`
- **Fix**: See OWASP guidance.

### HIGH — http_param → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\knowledge_graph\src\phantom.py:0`
- **Fix**: See OWASP guidance.

### HIGH — cli_arg → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\knowledge_graph\src\phantom.py:0`
- **Fix**: See OWASP guidance.

### HIGH — Password
- **CVSS**: 7.5  |  **CWE**: CWE-312  |  **OWASP**: Uncategorised
- **Location**: `modules\knowledge_graph\tests\test_knowledge_graph.py:0`
- **Fix**: See OWASP guidance.

### HIGH — http_param → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\learning\src\cve_ingester.py:0`
- **Fix**: See OWASP guidance.

### HIGH — http_param → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\learning\src\cve_ingester.py:0`
- **Fix**: See OWASP guidance.

### HIGH — http_param → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\learning\src\cve_ingester.py:0`
- **Fix**: See OWASP guidance.

### LOW — http_param → file_path
- **CVSS**: 3.1  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\learning\src\cve_ingester.py:0`
- **Fix**: See OWASP guidance.

### HIGH — deserialization → sql_query
- **CVSS**: 7.5  |  **CWE**: CWE-89  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\learning\src\knowledge_base.py:0`
- **Fix**: See OWASP guidance.

### HIGH — deserialization → sql_query
- **CVSS**: 7.5  |  **CWE**: CWE-89  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\learning\src\pattern_learner.py:0`
- **Fix**: See OWASP guidance.

### HIGH — env_var → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\oversight\src\covenant.py:0`
- **Fix**: See OWASP guidance.

### HIGH — env_var → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\oversight\src\covenant.py:0`
- **Fix**: See OWASP guidance.

### HIGH — http_param → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\oversight\src\covenant.py:0`
- **Fix**: See OWASP guidance.

### HIGH — http_param → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\oversight\src\covenant.py:0`
- **Fix**: See OWASP guidance.

### HIGH — http_param → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\oversight\src\covenant.py:0`
- **Fix**: See OWASP guidance.

### HIGH — cli_arg → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\oversight\src\covenant.py:0`
- **Fix**: See OWASP guidance.

### MEDIUM — High Entropy String
- **CVSS**: 5.3  |  **CWE**: CWE-312  |  **OWASP**: Uncategorised
- **Location**: `modules\oversight\src\oversight_engine.py:0`
- **Fix**: See OWASP guidance.

### MEDIUM — High Entropy String
- **CVSS**: 5.3  |  **CWE**: CWE-312  |  **OWASP**: Uncategorised
- **Location**: `modules\oversight\src\oversight_engine.py:0`
- **Fix**: See OWASP guidance.

### HIGH — Password
- **CVSS**: 7.5  |  **CWE**: CWE-312  |  **OWASP**: Uncategorised
- **Location**: `modules\oversight\tests\test_oversight_engine.py:0`
- **Fix**: See OWASP guidance.

### MEDIUM — High Entropy String
- **CVSS**: 5.3  |  **CWE**: CWE-312  |  **OWASP**: Uncategorised
- **Location**: `modules\oversight\tests\test_oversight_engine.py:0`
- **Fix**: See OWASP guidance.

### HIGH — cli_arg → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\reasoning\run_reasoning.py:0`
- **Fix**: See OWASP guidance.

### HIGH — cli_arg → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\reasoning\run_reasoning.py:0`
- **Fix**: See OWASP guidance.

### HIGH — cli_arg → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\reasoning\run_reasoning.py:0`
- **Fix**: See OWASP guidance.

### MEDIUM — Weak Hash
- **CVSS**: 5.3  |  **CWE**: CWE-327  |  **OWASP**: A02:2021 — Cryptographic Failures
- **Location**: `modules\reasoning\src\attack_graph.py:0`
- **Fix**: See OWASP guidance.

### MEDIUM — Weak Hash
- **CVSS**: 5.3  |  **CWE**: CWE-327  |  **OWASP**: A02:2021 — Cryptographic Failures
- **Location**: `modules\reasoning\src\attack_graph.py:0`
- **Fix**: See OWASP guidance.

### HIGH — http_param → sql_query
- **CVSS**: 7.5  |  **CWE**: CWE-89  |  **OWASP**: A03:2021 — Injection
- **Location**: `modules\reasoning\src\reasoning.py:0`
- **Fix**: See OWASP guidance.

### LOW — http_param → file_path
- **CVSS**: 3.1  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\reasoning\src\reasoning.py:0`
- **Fix**: See OWASP guidance.

### HIGH — cli_arg → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\reasoning\src\reasoning.py:0`
- **Fix**: See OWASP guidance.

### HIGH — cli_arg → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\reasoning\src\reasoning.py:0`
- **Fix**: See OWASP guidance.

### MEDIUM — High Entropy String
- **CVSS**: 5.3  |  **CWE**: CWE-312  |  **OWASP**: Uncategorised
- **Location**: `modules\reasoning\src\reasoning.py:0`
- **Fix**: See OWASP guidance.

### HIGH — Password
- **CVSS**: 7.5  |  **CWE**: CWE-312  |  **OWASP**: Uncategorised
- **Location**: `modules\reporting\tests\test_report_generator.py:0`
- **Fix**: See OWASP guidance.

### HIGH — cli_arg → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\scoring\src\cvss_scorer.py:0`
- **Fix**: See OWASP guidance.

### HIGH — cli_arg → file_path
- **CVSS**: 7.5  |  **CWE**: CWE-22  |  **OWASP**: A01:2021 — Broken Access Control
- **Location**: `modules\scoring\src\cvss_scorer.py:0`
- **Fix**: See OWASP guidance.

### HIGH — Password
- **CVSS**: 7.5  |  **CWE**: CWE-312  |  **OWASP**: Uncategorised
- **Location**: `modules\scoring\tests\test_cvss_scorer.py:0`
- **Fix**: See OWASP guidance.

### HIGH — Password
- **CVSS**: 7.5  |  **CWE**: CWE-312  |  **OWASP**: Uncategorised
- **Location**: `modules\simulation\tests\test_simulation_engine.py:0`
- **Fix**: See OWASP guidance.

## Audit Chain
- Chain intact: ✅
- Records: 11
- Chain intact — 11 record(s) verified.