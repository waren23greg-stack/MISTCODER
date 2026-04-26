# Module Specification: Universal Code Ingestion Engine

**Module ID:** `MSTC-MOD-01`
**Layer:** 1 — Ingestion
**Status:** Research / Specification
**Version:** 0.1.0
**Last Updated:** 2025

---

## 1. Overview

The Universal Code Ingestion Engine (UCIE) is the entry point of the MISTCODER pipeline. It is responsible for consuming every artifact that constitutes a software system — source code, compiled binaries, API definitions, infrastructure configuration, dependency manifests, and CI/CD pipeline definitions — and normalizing them into a unified, semantically rich intermediate representation (IR) that all downstream modules can reason over.

This is not a parser. Parsers understand syntax. The UCIE is designed to understand **structure, intent, and boundary**.

---

## 2. Ingestion Targets

### 2.1 Source Code

| Language Family | Examples | Priority |
|---|---|---|
| Systems languages | C, C++, Rust, Go, Zig | P0 |
| Application languages | Java, C#, Kotlin, Scala | P0 |
| Scripting / Dynamic | Python, Ruby, PHP, JavaScript, TypeScript | P0 |
| Smart contracts | Solidity, Vyper, Move | P1 |
| Shell / Infrastructure | Bash, PowerShell, HCL | P1 |
| Functional | Haskell, Erlang, Elixir | P2 |
| Legacy | COBOL, Fortran, Ada | P2 |

### 2.2 Compiled Artifacts

- ELF binaries (Linux x86-64, ARM64)
- PE/COFF binaries (Windows)
- Mach-O binaries (macOS, iOS)
- WebAssembly modules (.wasm)
- JVM bytecode (.class, .jar)
- .NET assemblies (.dll, .exe)
- Android DEX/ART

### 2.3 Interface Definitions

- OpenAPI / Swagger specifications (v2, v3)
- gRPC Protocol Buffer definitions (.proto)
- GraphQL schemas
- WSDL / SOAP definitions
- AsyncAPI specifications

### 2.4 Infrastructure as Code

- Terraform (.tf, .tfvars)
- Kubernetes manifests (YAML)
- Helm charts
- AWS CloudFormation / CDK
- Dockerfile / docker-compose
- Ansible playbooks
- GitHub Actions / GitLab CI / Jenkins pipelines

### 2.5 Dependency Manifests

- package.json / package-lock.json / yarn.lock
- requirements.txt / Pipfile / pyproject.toml
- go.mod / go.sum
- Cargo.toml / Cargo.lock
- pom.xml / build.gradle
- Gemfile / Gemfile.lock
- composer.json

---

## 3. Intermediate Representation Design

### 3.1 Goals

The IR must satisfy the following properties:

1. **Language-agnostic** — identical semantic constructs in different languages produce identical IR nodes
2. **Lossless for security-relevant properties** — no security-critical information is discarded during normalization
3. **Boundary-aware** — trust boundaries (process, network, privilege) are first-class citizens in the IR
4. **Traversable** — the IR must support efficient graph traversal for downstream taint analysis and attack path construction
5. **Extensible** — new language frontends can be added without modifying the IR schema

### 3.2 Core IR Node Types

```
IRNode
├── ProgramUnit          # A file, module, or compilation unit
├── Namespace            # Package, module, namespace
├── TypeDefinition       # Class, struct, interface, enum
├── FunctionDefinition   # Function, method, closure, lambda
│   ├── Parameter        # Typed input with source annotation
│   ├── ReturnValue      # Typed output
│   └── CallSite         # Invocation of another function
├── DataFlow
│   ├── Source           # Entry point for attacker-controlled data
│   ├── Sink             # Security-sensitive operation
│   ├── Sanitizer        # Validation or encoding operation
│   └── PropagationEdge  # Data movement between nodes
├── ControlFlow
│   ├── Branch           # Conditional execution
│   ├── Loop             # Iteration construct
│   └── ExceptionPath    # Error handling flow
├── TrustBoundary        # Process/network/privilege boundary crossing
│   ├── NetworkIngress   # Data entering from network
│   ├── NetworkEgress    # Data leaving to network
│   ├── ProcessSpawn     # Child process creation
│   ├── PrivilegeChange  # SUID, sudo, capability change
│   └── Deserialization  # Untrusted data materialization
├── CryptoPrimitive      # Cryptographic operation
│   ├── Algorithm        # Cipher, hash, KDF, RNG
│   ├── Key              # Key material reference
│   └── NonceIV          # Nonce/IV usage
└── Secret               # Credential, token, key material
    ├── Hardcoded        # Literal in source
    ├── EnvReference     # Environment variable reference
    └── ConfigReference  # External config reference
```

### 3.3 IR Serialization Format

The IR will be serialized as a directed property graph, stored in a format supporting:
- In-memory graph traversal during analysis
- Persistent storage for large codebases
- Diff computation between ingestion runs (detecting architectural changes)

Candidate formats under evaluation: property graph (Neo4j-compatible), LLVM bitcode IR extension, custom Protobuf schema.

---

## 4. Binary Lifting

For compiled artifacts without source code, the UCIE must reconstruct a security-analyzable representation from the binary.

### 4.1 Lifting Pipeline

```
Binary Artifact
      │
      ▼
Format Detection (ELF/PE/Mach-O/WASM/JVM)
      │
      ▼
Disassembly / Decompilation
(LLVM-based lifting, Ghidra integration, or custom decompiler)
      │
      ▼
Control Flow Graph Reconstruction
      │
      ▼
Type Recovery (variable types, struct layouts)
      │
      ▼
Symbol Resolution (debug symbols, DWARF, PDB if available)
      │
      ▼
IR Normalization (same schema as source-derived IR)
```

### 4.2 Research Challenges

- **Obfuscated binaries:** packed, encrypted, or virtualized code requires dynamic execution to recover
- **Type recovery fidelity:** reconstructed types are approximations — downstream analysis must account for uncertainty
- **Indirect call resolution:** function pointer dispatch and vtable calls require points-to analysis to resolve

---

## 5. Dependency Graph Construction

### 5.1 Scope

The dependency graph captures:
- Direct dependencies declared in manifests
- Transitive dependencies (dependencies of dependencies)
- Version pinning and resolution conflicts
- Known vulnerability associations (CVE linkage)
- License compliance metadata

### 5.2 Transitive Vulnerability Propagation

A critical insight: most dependency vulnerabilities are not in the declared dependency but in a transitive one. The UCIE must:

1. Resolve the full dependency tree (not just declared dependencies)
2. Map each resolved package version to the CVE/NVD database
3. Assess **reachability** — does the vulnerable code path actually get called by the application?
4. Weight findings by reachability, not just existence

### 5.3 Supply Chain Risk Indicators

Beyond known CVEs, the UCIE tracks:
- Packages with unusually broad system access for their stated purpose
- Recently transferred package ownership (common precursor to supply chain attacks)
- Packages with anomalous post-install scripts
- Dependencies sourced from non-canonical registries

---

## 6. CI/CD Pipeline Ingestion

CI/CD pipelines are an underanalyzed attack surface. The UCIE treats pipeline definitions as first-class security artifacts.

Security-relevant properties extracted from pipeline definitions:
- Secret injection points (where credentials enter the pipeline)
- Artifact signing and verification steps (or their absence)
- External action/plugin dependencies (GitHub Actions marketplace, etc.)
- Privileged operation sequences (deployment steps, infrastructure mutation)
- Branch protection rule compliance

---

## 7. Performance Requirements

| Metric | Target |
|---|---|
| Ingestion throughput (source code) | ≥ 100,000 lines/second |
| Binary lifting (per MB) | ≤ 30 seconds |
| Dependency graph construction | ≤ 60 seconds for 10,000 transitive deps |
| IR graph serialization | ≤ 10 seconds for 1M IR nodes |
| Incremental re-ingestion (changed files only) | ≤ 5 seconds for typical PR diff |

---

## 8. Open Research Questions

1. What is the minimal IR schema that preserves all security-relevant semantic properties across all target languages?
2. How do we handle languages with highly dynamic semantics (Python, Ruby, JavaScript) where type and call target are determined at runtime?
3. Can binary lifting achieve sufficient fidelity for meaningful taint analysis without source code?
4. What is the computational complexity of full transitive dependency reachability analysis at scale?
5. How should the IR represent uncertainty — cases where static analysis cannot determine a definitive answer?

---

## 9. Dependencies on Other Modules

| Module | Dependency Type |
|---|---|
| Static Analysis Engine (MOD-02) | Consumes IR output |
| Dynamic Analysis Engine (MOD-03) | Uses dependency graph for sandbox configuration |
| Reasoning Core (MOD-04) | Consumes full IR + dependency graph as knowledge input |

---

## 10. References

- LLVM Language Reference Manual — https://llvm.org/docs/LangRef.html
- Ghidra Reverse Engineering Framework — NSA/CSS
- FlowDroid: Precise Context, Flow, Field, Object-sensitive Taint Analysis — Arzt et al., 2014
- A Survey of Techniques for Dynamic Analysis — Ernst, 2003
- Software Composition Analysis: State of Practice — Plate et al., 2019

---

*MISTCODER Research Initiative — Module Specification MSTC-MOD-01 v0.1.0*
