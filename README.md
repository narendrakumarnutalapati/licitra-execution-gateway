# LICITRA Execution Gateway

Cryptographic execution integrity for AI agents.

LICITRA proves that every AI agent action was authorized, untampered, replay-resistant, and executed as approved — and produces an independently verifiable cryptographic proof of that fact.

## The Problem

Most AI agent security tools answer: *"Is this agent allowed to do this?"*

LICITRA answers a harder question: *"Did the action that actually executed match — byte for byte — what was approved?"*

An agent can be fully authenticated, fully policy-compliant, fully logged — and still execute an unauthorized action. LICITRA closes that gap.

## The Flow

```
Intent (LLM01 scan) → Policy (LLM10 rate limit) → Signed Ed25519 Ticket →
12-Check Verification (LLM05 schema + LLM01 rescan) →
MMR Audit Append → Tamper-Evident Evidence with Inclusion Proof
```

## OWASP LLM Coverage

| Risk | Name | Coverage |
|---|---|---|
| LLM01 | Prompt Injection | PRIMARY — scan at intent + rescan at verify |
| LLM05 | Improper Output Handling | PRIMARY — schema validation before execution |
| LLM06 | Excessive Agency | PRIMARY — CORE — full 12-check verify cycle |
| LLM10 | Unbounded Consumption | PRIMARY — rate limits + budget caps per agent |
| LLM02,03,04,07,08,09 | — | Out of scope — see docs/OWASP_COVERAGE.md |

## Why Not Just MCP Permissions?

MCP permissions answer: can this agent call this tool?

LICITRA answers: did the exact payload of that call match what was approved?

These are different problems. See [docs/MCP_POSITIONING.md](docs/MCP_POSITIONING.md).

## Enterprise Integration

```
[Identity]     Okta / Silverfort / Multifactor  →  identifies the agent
[Policy]       Microsoft AGT / Cerbos            →  decides what is allowed
[Credentials]  Clawvisor / Aembit               →  vaults secrets
[LICITRA]      Execution Gateway                →  proves exact action was approved
[Execution]    Google Workspace / Salesforce / MCP Tools
```

## Regulatory Context

- EU AI Act high-risk obligations: August 2026
- Colorado AI Act: enforceable June 2026
- LICITRA evidence chain is a direct compliance artifact at the action level

## Quickstart

```bash
make setup
make up
make seed
make demo-full
```

## Demo Commands

```bash
make demo-authorized      # ALLOWED + MMR proof + evidence_id
make demo-tamper          # BLOCKED + payload diff        [LLM06]
make demo-injection       # BLOCKED at intent creation    [LLM01]
make demo-schema          # BLOCKED at verify check 9     [LLM05]
make demo-ratelimit       # 5 ALLOWED then BLOCKED        [LLM10]
make demo-replay          # BLOCKED JTI replayed          [LLM06]
make demo-overscope       # BLOCKED action mismatch       [LLM06]
make demo-expired         # BLOCKED ticket expired        [LLM06]
make demo-fake            # BLOCKED agent not registered  [LLM06]
make demo-mmr-tamper      # MMR INTEGRITY VIOLATION
make demo-full            # all 10 attacks in sequence
```

## Research Foundation

This implementation is built on two published research primitives:

- [LICITRA-SENTRY](https://github.com/narendrakumarnutalapati/licitra-sentry) — pre-execution enforcement layer
- [LICITRA-MMR](https://github.com/narendrakumarnutalapati/licitra-mmr-core) — tamper-evident MMR audit chain

## Standards

- Reviewer: [OWASP GenAI Data Security Risks & Mitigations v1.0 (2026)](https://genai.owasp.org)
- Contributor: OWASP GenAI Best Practices v2
- Reference: OWASP Issue #802 — execution integrity gap in agentic systems

## Stack

- Backend: Python 3.12 + FastAPI
- Database: PostgreSQL + SQLAlchemy + Alembic
- Crypto: Ed25519 via PyNaCl + SHA-256
- Audit: Merkle Mountain Range (LICITRA-MMR)
- Tests: pytest (81+ tests)
- Frontend: React + Vite
- Container: Docker Compose

## License

MIT