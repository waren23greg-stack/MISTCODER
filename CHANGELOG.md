# CHANGELOG

All notable changes to MISTCODER are documented here.

---

## [0.5.0] — Phase 4: Reasoning Engine (feature/phase4-reasoning-engine)

### Added — Step 5: RELEASE
- `__init__.py` across all 11 module directories — package imports now work
- `.github/workflows/ci.yml` — CI pipeline: selftest + lint + covenant verify
  on Python 3.10, 3.11, 3.12 for every push and PR
- `README.md` rewritten — full architecture diagram, engine map, CLI reference
- `pr_template.md` — structured PR template for phase merge

### Added — Step 4: COVENANT
- `modules/oversight/src/covenant.py` — cryptographic audit engine
  - SHA-256 hash chain: every scan record linked to the previous
  - HMAC-SHA256 per record, keyed from machine identity
  - Tamper detection: verify() checks full chain integrity
  - Kill switch: scan blocked automatically if chain is broken
  - CVSS v3.1 base score mapping per finding severity
  - CWE → OWASP Top 10 2021 automatic classification
  - Compliance export: JSON / CSV / Markdown
- `mistcoder.py` patched: auto-records every scan, new `covenant` CLI command

### Added — Step 3: PHANTOM
- `modules/knowledge_graph/src/phantom.py` — unified TKG + attack path engine
  - `PhantomTKGBuilder` — constructs Threat Knowledge Graph from UnifiedIR
  - `PhantomPathFinder` — DFS exploit chain enumeration + CVSS scoring
  - `PhantomReasoner` — delegates to existing reasoning modules, self-contained fallback
  - `PhantomEngine` — public API: `ph.run(unified_ir)` → ranked `AttackPath` list
  - MITRE ATT&CK tactic tagging per path
- `mistcoder.py` patched: `--phantom` flag activates full pipeline

### Fixed — Step 3
- `mistcoder.py` scan dispatcher: now correctly walks directories (was silently
  skipping any target that wasn't a single file)
- `IR_BRIDGE` probe: checks 3 import paths before reporting missing

### Added — Step 2: NEXUS
- `mistcoder.py` — unified CLI: `scan`, `status`, `selftest`
- `modules/ingestion/src/ir_bridge.py` — normalises ORACLE + PARSER + URL_SCANNER
  outputs into a single UnifiedIR dict

### Added — Step 1: ORACLE
- `oracle.py` — CLI with `--self-test`, `--json`, `--watch` modes
- `modules/ingestion/src/python_ast_walker.py` — AST taint analysis
- `modules/ingestion/src/taint_model.py` — 8 source kinds, 12 sink kinds, 7 crypto issues
- `modules/ingestion/src/oracle_report.py` — terminal + JSON report with CWEs

---

## [0.1.0] — Phase 1: Foundation

### Added
- `README.md` — vision, 7-module architecture
- `SPEC.md` — MOD-04 Reasoning Core specification
- `SPEC2.md` — MOD-01 Ingestion Engine specification
- `ARCHITECTURE_V1.md` — high-level system diagrams
- `ETHICS.md`, `SECURITY.md`, `CONTRIBUTING.md` — policy documents
- Module directory scaffolding
