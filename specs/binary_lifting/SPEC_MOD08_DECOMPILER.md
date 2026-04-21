# MOD-08 Technical Specification — Binary Lifting & Decompilation

**Module ID:** MSTC-MOD-08  
**Layer:** 1 — Ingestion  
**Status:** Phase 3 Implementation  
**Version:** 0.1.0  

---

## 1. Overview

Binary Lifting converts compiled artifacts (ELF, PE, Mach-O, WebAssembly) into an architecture-agnostic Intermediate Representation (IR) compatible with MOD-01 and MOD-02.

**Current State:** String/metadata extraction only  
**Target State:** Full decompilation IR with cross-architecture support  

---

## 2. Decompilation Pipeline
Binary Input (ELF/PE/Mach-O/WASM) ↓ Format Parser (ELF/PE/etc.) ↓ Disassembler (x86/ARM/MIPS/WASM) ↓ Intermediate Representation (IR) Lowering ↓ Abstract IR (MOD-01 format) ↓ Analysis-Ready Output (to MOD-02)

Code

---

## 3. Supported Formats

### 3.1 ELF (Linux/Unix)

**Parser:** `ELFParser`

**Capabilities:**
- [x] Parse ELF headers, sections, symbols
- [x] Extract entry point and function symbols
- [ ] Build function boundaries
- [ ] Identify dangerous library calls
- [ ] Extract cross-references (callgraph)

### 3.2 PE (Windows)

**Parser:** `PEParser`

**Capabilities:**
- [x] Parse PE headers, sections, exports, imports
- [ ] Identify API calls (kernel32, ntdll, etc.)
- [ ] Extract entry point and exports
- [ ] Detect suspicious imports (WinExec, ShellExecute)

### 3.3 Mach-O (macOS)

**Parser:** `MachOParser` — NOT YET IMPLEMENTED

### 3.4 WebAssembly (WASM)

**Parser:** `WASMParser` — NOT YET IMPLEMENTED

---

## 4. Implementation Phases

### Phase 3.1 — ELF Parser (Week 1)
- [x] Basic structure parsing
- [ ] Symbol extraction and function boundaries
- [ ] Cross-reference building
- [ ] Dangerous pattern recognition

### Phase 3.2 — PE and Mach-O (Week 2)
- [x] PE import table parsing
- [ ] Mach-O dyld information
- [ ] API call classification
- [ ] Format-specific dangerous patterns

### Phase 3.3 — Disassembly & IR Lowering (Week 3)
- [ ] x86-64 disassembler
- [ ] ARM64 disassembler  
- [ ] IR lowering pipeline
- [ ] Cross-architecture normalization

### Phase 3.4 — Testing & Integration (Week 4)
- [x] 15+ test cases (ELF, PE, Mach-O, WASM)
- [ ] Integration with MOD-01 ingestion
- [ ] Performance benchmarks
- [ ] Fallback to string extraction mode

---

## 5. Performance Targets

| Operation | Target |
|-----------|--------|
| Parse 10MB ELF binary | < 2s |
| Extract symbols from 500-function binary | < 1s |
| Build callgraph (500 functions) | < 3s |
| Dangerous pattern detection | < 5s |

---

*MISTCODER Research Initiative — MOD-08 Specification v0.1.0*