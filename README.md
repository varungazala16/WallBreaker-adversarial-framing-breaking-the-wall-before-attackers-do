# ContextGuard

**Permission boundary stress tester for financial RAG / context management systems.**

Context management systems for finance have a non-negotiable requirement: a document one user isn't permitted to read must be completely undetectable to them — not just absent from results, but absent from error messages, result counts, and timing signals too. ContextGuard tests that boundary systematically, across five adversarial categories, before bugs reach production.

---

## What it does

ContextGuard ships with:

- **13 attack vectors** across five categories: direct access, prompt injection, role escalation, membership inference, and broad extraction
- **Three detection paths**: document-level leakage, sensitive phrase leakage, and metadata/error-message leakage
- **Two store implementations**: a `SecurePermissionStore` (correct reference) and a `VulnerablePermissionStore` (intentionally broken, for demo)
- **Weighted scoring** by severity (CRITICAL=3, HIGH=2, MEDIUM=1) with a letter grade
- **JSON export** for CI/CD integration (`--output results.json`)

---

## Quick start

```bash
pip install rich pyyaml
python demo.py            # test the vulnerable store (finds real bugs)
python demo.py --secure   # test the secure reference (A+ score)
python demo.py --compare  # side-by-side comparison
python demo.py --output report.json   # also export JSON
```

No API keys. No embeddings. No running services. One command.

---

## Example output

```
──────── ContextGuard — Permission Boundary Stress Tester ────────

 ID       │ Attack                        │ Category   │ Severity │ Result
──────────┼───────────────────────────────┼────────────┼──────────┼────────
 CT-001   │ Public User — Public Access   │ Control    │ CONTROL  │  PASS
 DA-001   │ Cross-Desk: Equity → Credit   │ Direct     │ CRITICAL │  BLOCKED
 PI-001   │ Prompt Injection — Admin KW   │ Injection  │ CRITICAL │  LEAKED  ← caught
 MI-001   │ Membership Inference — Falcon │ Membership │ MEDIUM   │  LEAKED  ← caught
 MI-002   │ M&A Target Company Probe      │ Membership │ HIGH     │  LEAKED  ← caught

 Score: 77.8 / 100   Grade: C
```

---

## Attack categories

| ID prefix | Category | What it tests |
|---|---|---|
| `CT` | Control | Legitimate access still works after hardening |
| `DA` | Direct Access | Cross-desk and cross-user permission enforcement |
| `PI` | Prompt Injection | Query-embedded instructions that try to override permission logic |
| `RE` | Role Escalation | Authority claims inside the query ("I am the CEO...") |
| `MI` | Membership Inference | Whether restricted document *existence* leaks via error messages |
| `BE` | Broad Extraction | Corpus enumeration and cross-client portfolio scraping |

---

## Vulnerability classes demonstrated

**Bug 1 — Authentication Bypass (CWE-287)**
`VulnerablePermissionStore` skips the permission check when the query contains the word `admin`. This mirrors real systems that naively parse user-supplied strings for access metadata.

**Bug 2 — Information Disclosure via Error Messages (CWE-209)**
When a restricted document is the top-ranked match, `VulnerablePermissionStore` echoes its title in the response metadata. The caller learns the document exists — a membership inference attack — even without reading its content. In finance, confirming that "Project Falcon" exists is itself insider information.

**Root cause — TOCTOU (Time-of-Check to Time-of-Use)**
`VulnerablePermissionStore` ranks *all* documents first, then filters by permission. The `SecurePermissionStore` applies permissions *before* any content is examined, so restricted documents are never scored, ranked, or referenced.

---

## Project structure

```
contextguard/
├── demo.py               # Entry point
├── requirements.txt      # rich, pyyaml only
├── config/
│   └── permissions.yaml  # User → role definitions
└── src/
    ├── corpus.py         # Synthetic financial document corpus
    ├── store.py          # SecurePermissionStore + VulnerablePermissionStore
    ├── attacks.py        # 13 attack vector definitions (pure data)
    ├── detector.py       # 3-path leakage detection engine
    ├── tester.py         # Orchestrator + result schema
    └── reporter.py       # Rich terminal output + JSON export
```

---

## Extending with custom attacks

Attack vectors are pure data — add your own without touching the engine:

```python
# src/attacks.py
AttackVector(
    id="DA-005",
    name="Custom: Contractor → Earnings Model",
    category=AttackCategory.DIRECT_ACCESS,
    severity=Severity.HIGH,
    description="Contractor account queries for pre-release earnings model.",
    attacker_user="contractor",
    query="Q2 earnings model forecast revenue guidance",
    target_restricted_doc_ids=["eq_004"],
    impact="Pre-release earnings data is material non-public information.",
),
```

---

## CI/CD integration

```bash
# Fail the build if any attack leaks
python demo.py --output report.json
# exit code 1 if leaked_count > 0
```

The JSON report includes attack IDs, severity, leaked document IDs, and phrase hits — structured for parsing by any CI system.

---

## Permissions model

Defined in `config/permissions.yaml`. Each user holds a list of roles; a document is accessible if the user holds at least one of the document's `allowed_roles`.

```yaml
users:
  alice:
    display_name: "Alice Chen (Equity Analyst)"
    roles: [public, equity_desk, user_alice]
  bob:
    display_name: "Bob Smith (Credit Analyst)"
    roles: [public, credit_desk, user_bob]
```

---

## Why this matters for Pacific

Pacific's context management system sits at the intersection of sensitive enterprise data and LLM-powered queries. The hard problem isn't retrieval quality — it's that a well-retrieved but wrongly-permissioned result is worse than no result at all.

ContextGuard is the test harness that answers: *"Before we ship this retrieval pipeline change, did we break any permission boundaries?"*

It runs in under 20ms on a synthetic corpus and is designed to be pointed at a real API endpoint with minimal configuration changes.
