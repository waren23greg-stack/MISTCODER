# MOD-01 -- Ingestion Engine

Responsible for consuming all forms of software artifacts as input to the MISTCODER pipeline.

## Accepts
- Source code (Python, JavaScript, Go, Rust, C/C++, Java, Solidity)
- Compiled binaries
- API specifications (OpenAPI, GraphQL schemas)
- Infrastructure-as-code (Terraform, Kubernetes YAML, Dockerfiles)
- Dependency manifests (package.json, requirements.txt, go.mod)

## Output
Normalized Intermediate Representation (IR) passed to MOD-02.

## Status
[ PHASE ] Research & Design

---

## Known Limitations (v0.1.0)

GAP-01  JS secret detection missing
        JavaScript parser does not flag credential assignments.
        Python parser (PythonParser) handles this correctly.
        Fix target: v0.2.0

GAP-02  JS edge graph not built
        JavaScriptParser produces no call edges.
        Functions are not linked to dangerous calls they contain.
        Fix target: v0.2.0

GAP-03  No taint flow tracing
        Neither parser traces untrusted input from entry point
        to dangerous call. This is MOD-02 responsibility.
