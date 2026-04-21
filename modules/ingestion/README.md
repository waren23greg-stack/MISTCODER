# ORACLE Engine — MISTCODER Phase 2

**Module:** `MSTC-MOD-01 / MOD-02 prototype`  
**Status:** Working prototype — zero external dependencies  
**Engine:** Python AST Walker + Taint Engine + Secret Scanner

---

## What ORACLE Does

ORACLE is MISTCODER's first working intelligence engine. It scans Python codebases using the stdlib `ast` module and finds:

| Category | What it detects |
|----------|----------------|
| **Taint flows** | Source → sink paths: SQL injection, command injection, SSTI, deserialization, path traversal, XSS, open redirect |
| **Crypto misuse** | MD5/SHA1, ECB mode, insecure random, TLS verify=False, hardcoded keys |
| **Secrets** | API keys, passwords, private keys, AWS/GitHub/Stripe credentials, high-entropy strings |

Every finding includes: severity, CWE reference, source+sink location, and specific remediation guidance with code example.

---

## Files

```
oracle.py                           ← Entry point CLI
modules/ingestion/src/
  taint_model.py                    ← Data types: sources, sinks, flows, findings
  python_ast_walker.py              ← Real AST-based analysis engine
  oracle_report.py                  ← Terminal + JSON report renderer
```

---

## Usage

```bash
# Scan a directory
python oracle.py src/

# Scan a single file  
python oracle.py app.py

# Export to JSON (feeds modules/knowledge_graph/)
python oracle.py src/ --json oracle_report.json

# Watch mode — rescan on save
python oracle.py src/ --watch

# Self-test (verifies engine works correctly)
python oracle.py --self-test
```

---

## JSON Output → Knowledge Graph Integration

The `--json` flag exports a structured report that feeds directly into `modules/knowledge_graph/`:

```json
{
  "mistcoder_version": "0.2.0-oracle",
  "engine": "ORACLE",
  "files": [
    {
      "path": "src/auth/views.py",
      "taint_flows": [
        {
          "severity": "CRITICAL",
          "cwe": "CWE-89",
          "source_kind": "http_param",
          "sink_kind": "sql_query",
          "source_loc": "src/auth/views.py:24",
          "sink_loc": "src/auth/views.py:31"
        }
      ]
    }
  ]
}
```

---

## What's Next (Step 2 — SENTINEL)

SENTINEL will add:
- **Binary analysis** integration with your existing `modules/binary_lifting/`
- **Dependency CVE lookup** against NVD feeds
- **Multi-file inter-procedural taint** (tracking taint across function calls)

---

*MISTCODER ORACLE — Phase 2 Prototype — Zero external dependencies*
