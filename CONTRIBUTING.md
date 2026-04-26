# Contributing to MISTCODER

**Project:** MISTCODER
**Core Owner:** waren23greg-stack
**Repository:** https://github.com/waren23greg-stack/MISTCODER
**Status:** Early Research & Design Phase — contributions are by invitation only at this stage

---

## 1. Intellectual Property Notice

MISTCODER is an original conceptual and technical work conceived, designed,
and owned by the repository owner (waren23greg-stack). The architecture,
module designs, reasoning frameworks, terminology, pipeline structures, and
research papers contained in this repository represent proprietary intellectual
property.

Any individual or organization that:
-- Reproduces this architecture in whole or in part
-- Derives a product, tool, or system substantially similar to MISTCODER
-- Uses the terminology, module naming conventions, or pipeline design
   of this project without explicit written permission

...is subject to intellectual property claims under applicable copyright,
trade secret, and unfair competition law.

This repository is public for the purpose of establishing prior art and
timestamped authorship — not for unrestricted reuse.

---

## 2. Prior Art Declaration

The following concepts are original to this project and documented here
as prior art, with commit timestamps serving as proof of conception date:

  CONCEPT-01  The five-module MISTCODER pipeline
              (Ingestion → Analysis → Reasoning → Simulation → Oversight)

  CONCEPT-02  Adversarial cognition modeling via heuristic-guided graph
              traversal on a directed property graph of software attack
              surfaces

  CONCEPT-03  Behavioral anomaly-based novelty detection for vulnerability
              classes with no prior CVE signature

  CONCEPT-04  Policy-gated white-hat simulation with cryptographic audit
              logging and hardware-level kill switch design

  CONCEPT-05  The MISTCODER module naming convention:
              MOD-01 through MOD-05 and the interface specification schema

  CONCEPT-06  The term "MISTCODER" as a project identity and acronym:
              Multi-Intelligence Security & Threat Cognition,
              Offensive Detection, Exploitation Reasoning

Any system launched after the commit timestamps of this repository that
reproduces these concepts without attribution is subject to dispute.

---

## 3. How to Contribute (Invitation Only)

At this stage, MISTCODER does not accept unsolicited pull requests.

If you wish to contribute:

  Step 1  Open an Issue titled: "Contribution Request — [Your Name] — [Topic]"
  Step 2  Describe your proposed contribution in detail
  Step 3  Wait for explicit written approval from the core owner
  Step 4  Sign the Contributor Agreement (to be issued on approval)
  Step 5  Submit your pull request only after agreement is signed

Pull requests submitted without prior approval will be closed without review.

---

## 4. Local Development Setup (for approved contributors)

```bash
git clone https://github.com/waren23greg-stack/MISTCODER.git
cd MISTCODER
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install pytest ruff
```

Run the same checks used by CI before opening a pull request:

```bash
python mistcoder.py status
python mistcoder.py selftest
python oracle.py --self-test
python modules/oversight/src/covenant.py selftest
python modules/knowledge_graph/src/phantom.py
pytest modules/ --tb=short -q --ignore=modules/binary_lifting/tests
ruff check . --ignore E501,E402,F401
```

> Run these commands from the repository root so `pytest.ini` can apply the local import path configuration.

---

## 5. Contributor Agreement (Summary)

All approved contributors must agree to the following before any contribution
is accepted:

  4.1  All contributions become the intellectual property of the MISTCODER
       project and its core owner upon merge.

  4.2  Contributors retain credit in the CONTRIBUTORS file and in commit
       history, but waive ownership claims over merged work.

  4.3  Contributors may not use their contribution as the basis for a
       competing project, tool, or product.

  4.4  Contributors may not disclose non-public architectural details,
       research findings, or roadmap information shared during the
       contribution process.

---

## 6. Code Standards

When contributions are eventually accepted, the following standards apply:

  Language       Python 3.10+ (CI-tested on 3.10–3.12)
  Style          PEP 8 strictly enforced
  Tests          All code must include unit tests (pytest)
  Documentation  All functions must have docstrings (Google style)
  Security       No secrets, tokens, or credentials in any commit
  Commits        Conventional Commits format required
                 feat: / fix: / docs: / test: / refactor:

---

## 7. Reporting Issues

Issues are welcome for:
  -- Bug reports (once code exists)
  -- Research discussions
  -- Architecture feedback

Issues are not a mechanism for claiming ownership of ideas discussed
in this repository.

---

## 8. Code of Conduct

All contributors and participants are expected to follow
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

---

## 9. Contact

For contribution requests, licensing inquiries, or IP concerns:
Open a GitHub Issue with the label: [CONTACT]

---

*MISTCODER -- Core Owner: waren23greg-stack*
*All rights reserved. Public visibility does not imply open license.*
