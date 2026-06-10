# AGENTS.md

**Status: COMPLETE — Days 0-13 implemented**

**Project:** LICITRA Execution Gateway  
**Mission:** Cryptographic execution integrity for AI agents.  
**OWASP Coverage:** LLM01 · LLM05 · LLM06 · LLM10

## Enforcement Rules

- Never bypass ticket verification
- Never allow execution without verification
- Deny by default on all policy decisions
- Ed25519 signatures mandatory for all tickets
- JTI replay protection enforced on every verify call using `SELECT FOR UPDATE`

## Function Contracts

- `scan_for_injection()` runs on every intent AND every verify payload re-scan
- `validate_output_schema()` runs at verify check 9
- `check_rate_limit()` runs on every policy evaluation using `SELECT FOR UPDATE`
- `check_budget()` runs on every policy evaluation using `SELECT FOR UPDATE`
- `increment_counters()` called ONLY after confirmed execution — never at verify time

## MMR Audit Chain

- MMR (Merkle Mountain Range) for audit chain — NEVER a simple linked chain
- `leaf_index` MUST be bound into `leaf_hash` to prevent position-swap attacks
- MMR inclusion proof stored at INSERT time, not query time

## Verification

- Verification diff produced on any value mismatch
- All 12 verification checks run in order — first failure terminates

## Testing

- Every feature has pytest tests — minimum 81 total

## OWASP Function Map

| Risk | Function | Purpose |
|------|----------|---------|
| LLM01 | `scan_for_injection()` | Prompt injection detection |
| LLM05 | `validate_output_schema()` | Improper output handling |
| LLM06 | core verify cycle | Excessive agency |
| LLM10 | `check_rate_limit()` / `check_budget()` | Unbounded consumption |

## Stack

`FastAPI` · `PostgreSQL` · `React + Vite` · `Ed25519 / PyNaCl` · `SHA-256` · `MMR` · `jsonschema` · `ReportLab` · `pytest` · `Docker`

## Test Counts

Test counts: 54 unit + 37 integration = 91 total

## Research Alignment

This gateway implements a subset of the LICITRA research series.

Implemented: execution ticket layer, MMR ledger primitive,
12-check verification, LLM01/05/06/10 OWASP coverage.

Not implemented in v1.0: witnessed transparency layer,
epoch anchoring, PII detection, delegation escalation
blocking.

See README.md ## Implementation Scope for full details.