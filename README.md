# LICITRA Execution Gateway

> Cryptographic execution integrity for AI agents.
> Every action authorized. Every deviation blocked.
> Every event tamper-evident.

[![Tests](https://img.shields.io/badge/tests-91%20passing-brightgreen)]()
[![OWASP](https://img.shields.io/badge/OWASP-LLM01%20LLM05%20LLM06%20LLM10-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20634496.svg)](https://doi.org/10.5281/zenodo.20634496)

**Website:** https://licitra.app

## The Problem

AI agents can take real actions: send emails, query
databases, modify records. Nothing in current AI
infrastructure proves that the action executed matches
what was approved, or detects if an agent was hijacked
between approval and execution.

## What LICITRA Does

LICITRA is a cryptographic execution layer that sits
between an AI agent and its tools. Before any action
executes, LICITRA:

- **Scans the intent** for prompt injection (LLM01)
- **Issues a signed execution ticket** binding the
  agent, action, resource, and payload to a single
  cryptographic commitment
- **Runs 12 verification checks** at execution time —
  signature validity, payload hash, action binding,
  JTI replay prevention, output schema (LLM05),
  scope enforcement (LLM06), rate limits (LLM10)
- **Appends every decision** to a Merkle Mountain Range
  audit chain — tamper-evident, inclusion-provable

If any check fails, the action is **blocked** and
evidence is written. If the audit chain is modified
after the fact, the MMR root hash changes and
integrity violation is detected immediately.

## Architecture

```
User Intent
|
v
+------------------------------------------+
|  INJECTION SCAN (LLM01)                  |
|  scan_for_injection() - 8 patterns       |
|  INJ001-INJ008, HIGH/MEDIUM severity     |
+------------------+-----------------------+
                   | PASS
                   v
+------------------------------------------+
|  POLICY EVALUATION (LLM10)               |
|  check_rate_limit() - per-agent hourly   |
|  check_budget() - daily spend cap        |
+------------------+-----------------------+
                   | ALLOWED
                   v
+------------------------------------------+
|  TICKET ISSUANCE                         |
|  Ed25519 signed execution ticket         |
|  payload_hash, action, resource bound    |
|  JTI for replay prevention               |
+------------------+-----------------------+
                   | TICKET
                   v
+------------------------------------------+
|  12-CHECK VERIFICATION (LLM06)           |
|  1.  Agent registered                    |
|  2.  Ticket exists in DB                 |
|  3.  Signature valid (Ed25519)           |
|  4.  Ticket not expired                  |
|  5.  JTI not replayed                    |
|  6.  Action matches ticket               |
|  7.  Resource matches ticket             |
|  8.  Payload hash matches ticket         |
|  9.  Output schema valid (LLM05)         |
|  10. Injection rescan on payload         |
|  11. Agent scope check                   |
|  12. Decision binding                    |
+------------------+-----------------------+
                   | ALLOWED or BLOCKED
                   v
+------------------------------------------+
|  MMR AUDIT CHAIN                         |
|  Every decision -> MMR leaf              |
|  SHA-256 leaf hash with position binding |
|  Inclusion proof stored per event        |
|  mmr_detect_tampering() on any read      |
+------------------------------------------+
```

## Quick Start

```bash
git clone https://github.com/narendrakumarnutalapati/licitra-execution-gateway
cd licitra-execution-gateway
cp .env.example .env
make up        # starts API + React dashboard + PostgreSQL
make seed      # populates with 46 realistic events
# Open http://localhost:5173
```

## Run the Attack Demos

```bash
make demo-full        # all 10 attacks in sequence
make demo-tamper      # tampered payload — BLOCKED at Check 8
make demo-injection   # prompt injection — BLOCKED at intent
make demo-schema      # schema violation — BLOCKED at Check 9
make demo-ratelimit   # rate limiting — BLOCKED at policy
```

Or open **http://localhost:5173/demo** and click
**Run Attack** from the browser — no terminal needed.

## Dashboard

| Page | What it shows |
|---|---|
| Overview | Live metrics: allowed, blocked, injections, schema violations, rate limits |
| Actions | Last 50 audit events with OWASP badges, clickable evidence links |
| MMR | Current root hash, leaf count, INTACT/TAMPERED status |
| OWASP | Coverage cards with live counts for LLM01/05/06/10 |
| Verify | Manual MMR inclusion proof verifier with auto-fill |
| Demo | 10 attack cards — run from browser with live results |

## API

| Method | Endpoint | Description |
|---|---|---|
| GET | /healthz | System health + MMR status |
| POST | /agents/register | Register agent with policy rules |
| POST | /intent/create | Create intent with injection scan |
| POST | /policy/evaluate | Evaluate against agent policy |
| POST | /tickets/issue | Issue Ed25519 signed ticket |
| POST | /actions/verify | 12-check verification |
| GET | /audit | Recent audit events |
| GET | /audit/root | MMR root hash + integrity |
| POST | /audit/verify-proof | Verify MMR inclusion proof |
| GET | /evidence/{id} | Full evidence record |
| GET | /evidence/{id}/pdf | PDF evidence download |
| GET | /metrics | Live counters by attack type |
| POST | /metrics/snapshot | Persist metrics snapshot |
| GET | /metrics/history | Last 10 metric snapshots |

## OWASP LLM Top 10 Coverage

| Risk | Status | Implementation |
|---|---|---|
| LLM01 Prompt Injection | ✅ Full | 8 patterns, HIGH blocks immediately, scan at intent + rescan at verify |
| LLM05 Improper Output Handling | ✅ Full | JSON Schema validation at Check 9, additionalProperties enforced |
| LLM06 Excessive Agency | ✅ Full | 12-check cryptographic verification, Ed25519 tickets, MMR audit |
| LLM10 Unbounded Consumption | ✅ Full | Per-agent hourly limits, daily limits, budget caps |
| LLM02-04, LLM07-09 | ⬜ Out of scope | See docs/OWASP_COVERAGE.md |

## Test Suite

```bash
make test              # 54 unit tests
make test-integration  # 37 integration tests
make test-all          # 91 total
```

All tests run inside Docker — no local Python setup needed.

## Research Foundation

This gateway implements the LICITRA framework:

- **LICITRA-SENTRY** — Execution tickets and witnessed
  transparency for runtime enforcement
  DOI: https://doi.org/10.5281/zenodo.18860290

- **LICITRA-MMR-CORE** — Merkle Mountain Range audit
  ledger for tamper-evident accountability
  DOI: https://doi.org/10.5281/zenodo.18843032

- **LICITRA Execution Gateway v1.0.1** — Reference implementation  
  DOI: https://doi.org/10.5281/zenodo.20634496

OWASP GenAI Data Security Risks v1.0 — credited reviewer

## Implementation Scope

This gateway implements the execution ticket layer and
MMR ledger primitive from the LICITRA research series:

**Implemented from LICITRA-SENTRY:**
- Ed25519 signed execution tickets with payload hash binding
- JTI-based replay attack prevention
- Payload modification detection (Check 8)
- 12-check cryptographic verification pipeline
- Tamper-evident audit chain with inclusion proofs

**Implemented from LICITRA-MMR-CORE:**
- Merkle Mountain Range append-only ledger
- O(log N) inclusion proofs verifiable by third parties
- Position-binding leaf hashes preventing swap attacks
- `mmr_detect_tampering()` on every read

**Not yet implemented (roadmap v2.0):**
- Witnessed transparency layer — CT-style external witnesses
  co-signing epoch root hashes. Without witnesses,
  tamper-evidence requires operator honesty. This is a
  known limitation of v1.0.
- Epoch anchoring — committing MMR root hashes to an
  external transparency log or blockchain
- PII exfiltration detection
- Delegation escalation blocking

## Stack

Python 3.12 · FastAPI · PostgreSQL · SQLAlchemy ·
Ed25519/PyNaCl · SHA-256 · Merkle Mountain Range ·
jsonschema · ReportLab · React/Vite · Docker Compose

## License

MIT