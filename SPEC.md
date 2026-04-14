# Module Specification: AI Reasoning & Attack Path Construction

**Module ID:** `MSTC-MOD-04`
**Layer:** 3 — Reasoning Core
**Status:** Research / Specification
**Version:** 0.1.0
**Last Updated:** 2025

---

## 1. Overview

The AI Reasoning Core is the intellectual center of MISTCODER. It is the module that separates MISTCODER from every existing security tool.

Where other tools enumerate, MISTCODER **reasons**. Where other tools report individual findings, MISTCODER **constructs narratives** — complete, coherent accounts of how an adversary would compromise a target system, step by step, leveraging combinations of weaknesses that no individual finding would flag as critical.

This module receives the normalized IR and analysis findings from Modules 01–03 and produces:

1. A complete **threat knowledge graph** of the target system
2. A ranked set of **multi-step attack paths** with exploit chain modeling
3. **Novel vulnerability class hypotheses** — potential weakness archetypes not yet in any CVE database
4. A human-readable **adversarial narrative** for each critical finding

---

## 2. Threat Knowledge Graph

### 2.1 Definition

The Threat Knowledge Graph (TKG) is a directed property graph that encodes the complete security landscape of the target system. It is constructed from the outputs of all upstream modules and serves as the primary data structure for all reasoning operations.

### 2.2 Node Types

```
TKGNode
├── Asset                  # Something an adversary wants
│   ├── DataStore          # Database, file, cache, secret store
│   ├── Credential         # Authentication material
│   ├── Capability         # Privileged operation access
│   └── ExternalSystem     # Connected downstream system
├── WeaknessNode           # A discovered vulnerability or flaw
│   ├── ConfirmedVuln      # Verified, exploitable weakness
│   ├── ProbableVuln       # High-confidence candidate
│   └── HypotheticalVuln   # Reasoning-derived candidate
├── TrustBoundary          # From IR — process/network/privilege boundary
├── AttackerPosition       # Where an attacker can reach from
│   ├── External           # Unauthenticated internet attacker
│   ├── AuthenticatedUser  # Legitimate user with credentials
│   ├── InternalNetwork    # Attacker on internal network
│   └── CodeExecution      # Attacker with arbitrary code execution
└── MitigationNode         # Existing defensive control
    ├── Authentication      # Auth check
    ├── Authorization       # Authz check
    ├── Sanitization        # Input validation/encoding
    ├── Encryption          # Data protection
    └── RateLimit           # Abuse prevention
```

### 2.3 Edge Types

```
TKGEdge
├── Exploits               # WeaknessNode → Asset (attacker exploits weakness to reach asset)
├── Enables                # WeaknessNode → AttackerPosition (grants new position)
├── Bypasses               # WeaknessNode → MitigationNode (neutralizes defense)
├── Precondition           # WeaknessNode → WeaknessNode (A must be exploited before B)
├── Amplifies              # WeaknessNode → WeaknessNode (A makes B more severe)
├── ProtectedBy            # Asset → MitigationNode (defense guards asset)
└── Crosses                # AttackerPosition → TrustBoundary (movement across boundary)
```

### 2.4 Graph Construction Process

```
Stage 1: Node Population
├── Import all WeaknessNodes from Static Analysis (MOD-02)
├── Import all WeaknessNodes from Dynamic Analysis (MOD-03)
├── Import all TrustBoundary nodes from IR (MOD-01)
├── Infer AssetNodes from data classification analysis
└── Infer MitigationNodes from code patterns

Stage 2: Edge Inference
├── Taint flow edges (from data flow analysis)
├── Privilege transition edges (from IR trust boundary analysis)
├── Precondition edges (from vulnerability semantic analysis)
└── Amplification edges (from co-location and dependency analysis)

Stage 3: Attacker Position Seeding
├── Enumerate all external entry points (APIs, web interfaces, files)
├── Define initial attacker positions for each threat model scenario
└── Compute reachability from each starting position

Stage 4: Graph Validation
├── Consistency check (no orphaned nodes, no impossible edges)
├── Completeness assessment (flag under-analyzed regions)
└── Confidence scoring (propagate uncertainty from upstream modules)
```

---

## 3. Attack Path Construction

### 3.1 Problem Definition

Given:
- A Threat Knowledge Graph G
- An initial attacker position A₀
- A target asset T

Find: All paths P = [A₀, W₁, A₁, W₂, A₂, ..., Wₙ, T] where:
- Each Wᵢ is a WeaknessNode exploitable from position Aᵢ₋₁
- Each Aᵢ is the attacker position achieved by exploiting Wᵢ
- The path terminates when the attacker reaches asset T

### 3.2 Path Scoring

Each path is scored on multiple dimensions:

```
PathScore = f(Exploitability, Impact, Probability, Detectability)

Where:
  Exploitability = weighted average of CVSS Exploitability scores across path
  Impact         = maximum asset sensitivity × breach completeness
  Probability    = product of individual step success probabilities
  Detectability  = inverse of average detection probability across steps
```

Critical insight: A path of five medium-severity steps may score higher than a single critical vulnerability if:
- The five-step path has lower detectability
- The five-step path requires no public exploit code
- The five-step path terminates at a higher-value asset

### 3.3 Adversarial Prioritization

MISTCODER does not simply rank vulnerabilities by CVSS score. It ranks **attack paths** by adversarial value. The question is always:

> *"If I were the most capable, patient, and motivated adversary with access to this system's attack surface, which path would I take?"*

This requires modeling adversary capability tiers:

| Tier | Profile | Capability |
|---|---|---|
| T1 | Opportunistic | Runs public exploit tools, no custom capability |
| T2 | Skilled | Adapts public exploits, limited custom tooling |
| T3 | Advanced | Custom exploit development, multi-stage operations |
| T4 | Nation-state | Zero-day capability, unlimited patience, insider access |

Attack paths are evaluated against each tier. A path only exploitable by T4 adversaries carries different remediation urgency than one exploitable by T1.

---

## 4. Novel Vulnerability Class Inference

This is the most ambitious and least-defined component of the Reasoning Core. The goal is for MISTCODER to identify **vulnerability classes that do not yet exist in any database** — to discover, from first principles, that a particular pattern of code is exploitable in a way no one has publicly documented.

### 4.1 Approach

This is a research-open problem. Candidate approaches:

**Approach A: Semantic Anomaly Detection**
Train a model on the semantic properties of known vulnerable code patterns. Identify code regions that share semantic similarity with known-vulnerable patterns but differ in surface syntax — these are candidates for novel vulnerability classes.

**Approach B: Constraint Satisfaction Reasoning**
Express security properties as formal constraints. Use a theorem prover or SMT solver to find inputs that violate these constraints. Violations that don't match known CVE patterns are candidate novel classes.

**Approach C: Adversarial Hypothesis Generation**
Use a large language model trained on security research to generate hypotheses about how a given code region could be exploited. Validate hypotheses through dynamic analysis in sandbox. Confirmed hypotheses that don't match known CVEs are novel.

**Approach D: Cross-System Pattern Synthesis**
Analyze findings across many different software systems. Identify recurring structural patterns that produce the same class of finding. Abstract the pattern into a vulnerability class definition.

### 4.2 Research Requirements

- A formal definition of "vulnerability class" that is precise enough to distinguish new classes from variations of existing ones
- A validation mechanism that confirms hypothetical findings are genuine without requiring human review of every candidate
- A publication pipeline for responsible disclosure of genuinely novel classes

---

## 5. Explainability Engine

Every finding MISTCODER produces must be accompanied by a complete, human-readable reasoning chain. This is not optional — it is a core design requirement driven by both the ethics charter and practical usability.

### 5.1 Finding Report Structure

```yaml
finding:
  id: MSTC-2025-00001
  title: "Authentication bypass via JWT algorithm confusion"
  severity: CRITICAL
  cvss_score: 9.1
  cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

  reasoning_chain:
    - step: 1
      observation: "JWT validation in AuthService.verify() accepts algorithm parameter from token header"
      evidence: "src/auth/service.py:142 — jwt.decode(token, key, algorithms=[header['alg']])"
      significance: "Attacker controls algorithm selection"

    - step: 2
      observation: "RS256 public key is accessible via JWKS endpoint at /.well-known/jwks.json"
      evidence: "src/api/routes.py:67 — Public route, no authentication required"
      significance: "Attacker can retrieve the public key used for RS256 verification"

    - step: 3
      observation: "HS256 algorithm uses symmetric key — if RS256 public key is used as HS256 secret, signatures verify successfully"
      evidence: "Algorithmic property of JWT libraries — documented in CVE-2015-9235 class"
      significance: "Attacker can forge valid tokens by signing with RS256 public key using HS256"

    - step: 4
      observation: "Forged token with admin:true claim grants full administrative access"
      evidence: "src/api/middleware.py:89 — role check reads directly from token claims"
      significance: "Complete authentication bypass achieved"

  attack_path:
    entry_point: "External unauthenticated attacker"
    steps:
      - "Retrieve public key from /.well-known/jwks.json"
      - "Craft JWT with algorithm=HS256, admin=true, sign with RS256 public key"
      - "Submit forged token to any authenticated API endpoint"
    outcome: "Full administrative access to all API endpoints"

  remediation:
    immediate: "Pin accepted algorithms to RS256 only — do not allow token header to specify algorithm"
    code_fix: "jwt.decode(token, key, algorithms=['RS256'])  # Explicit allowlist"
    verification: "Confirm no other JWT decode call sites accept algorithm from token"

  references:
    - "CVE-2015-9235 — JWT algorithm confusion"
    - "Auth0 Security Bulletin 2015-04"
```

---

## 6. Performance Requirements

| Operation | Target |
|---|---|
| TKG construction (1M IR nodes) | ≤ 5 minutes |
| Attack path enumeration (top 100 paths) | ≤ 10 minutes |
| Single finding report generation | ≤ 30 seconds |
| Novel vulnerability class inference | Best-effort, no hard limit |

---

## 7. Open Research Questions

1. What graph algorithms are most effective for attack path construction in realistic TKGs (which may have millions of nodes)?
2. How do we handle uncertainty propagation — when upstream modules express low confidence, how does that affect path scoring?
3. Is it possible to formally define "novel vulnerability class" in a way that is both precise and tractable to compute?
4. How do we prevent the reasoning core from producing false-positive attack paths that appear plausible but are not actually exploitable?
5. What is the right balance between exhaustive path enumeration and targeted adversarial prioritization?

---

## 8. References

- Idika & Mathur — *A Survey of Malware Detection Techniques* (2007)
- Sheyner et al. — *Automated Generation and Analysis of Attack Graphs* (2002)
- Ou et al. — *A Scalable Approach to Attack Graph Generation* (2006)
- MITRE ATT&CK Framework — https://attack.mitre.org
- MITRE CAPEC — Common Attack Pattern Enumeration and Classification
- NVD / CVE Database — https://nvd.nist.gov
- EPSS — Exploit Prediction Scoring System — https://www.first.org/epss

---

*MISTCODER Research Initiative — Module Specification MSTC-MOD-04 v0.1.0*
