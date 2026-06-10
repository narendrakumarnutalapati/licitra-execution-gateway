# LICITRA Execution Gateway

A cryptographic execution integrity gateway for AI agents that proves every action was authorized, untampered, and executed exactly as approved.

It solves the gap between *"was this agent allowed to act?"* and *"did the action that actually executed match — byte for byte — what was approved?"*

## What It Does

- **Stops prompt injection before execution** — `scan_for_injection()` runs on every intent at creation and again at every verify call, blocking LLM01 attacks before any ticket is issued or action executed
- **Enforces output schema contracts** — every agent declares its output schema at registration; `validate_output_schema()` runs at verify check 9, blocking extra fields like `bcc: exfil@shadow.com` (LLM05)
- **Prevents payload tampering, replay, and scope escalation** — 12 sequential cryptographic checks bind the exact approved payload to the Ed25519-signed ticket; any mismatch, replay, or action substitution is blocked at verify time (LLM06)
- **Enforces per-agent rate limits and budget caps** — `check_rate_limit()` and `check_budget()` run at every policy evaluation; agents cannot exceed their declared hourly action count or daily spend (LLM10)

## Architecture

```
Agent
  │
  ▼
POST /intent/create  ──[LLM01: injection scan]──► BLOCKED if injection found
  │
  ▼
POST /policy/evaluate ─[LLM10: rate limit + budget]─► BLOCKED if over limit
  │
  ▼
POST /tickets/issue  ──[Ed25519 signed ticket, payload hash bound]
  │
  ▼
POST /actions/verify ── 12 checks in order:
  │  Check  1: agent_registered          [LLM06]
  │  Check  2: ticket_exists             [LLM06]
  │  Check  3: signature_valid           [LLM06]
  │  Check  4: not_expired               [LLM06]
  │  Check  5: jti_not_replayed          [LLM06]
  │  Check  6: action_matches            [LLM06]
  │  Check  7: resource_matches          [LLM06]
  │  Check  8: payload_hash_matches      [LLM06]
  │  Check  9: output_schema_valid       [LLM05]
  │  Check 10: injection_rescan          [LLM01]
  │  Check 11: agent_scope               [LLM06]
  │  Check 12: decision_binding          [LLM06]
  │
  ▼
MMR Audit Append ── leaf_index bound into leaf_hash (position-swap resistant)
  │
  ▼
GET /evidence/{id} ── tamper-evident record with MMR inclusion proof
```

## Quick Start

```bash
git clone https://github.com/narendrakumarnutalapati/licitra-execution-gateway
cd licitra-execution-gateway
cp .env.example .env
make up
make seed
# Open http://localhost:5173
```

## Run the Attack Demos

```bash
make demo-full        # All 10 attacks in sequence
make demo-tamper      # Tampered payload
make demo-injection   # Prompt injection
make demo-schema      # Schema violation
make demo-ratelimit   # Rate limiting
```

Or open [http://localhost:5173/demo](http://localhost:5173/demo) and click **Run Attack** from the browser.

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Health check, MMR integrity status |
| `POST` | `/agents/register` | Register an agent with allowed actions and output schema |
| `POST` | `/intent/create` | Create intent — runs injection scan |
| `POST` | `/policy/evaluate` | Evaluate policy — rate limit + budget check |
| `POST` | `/tickets/issue` | Issue Ed25519-signed execution ticket |
| `POST` | `/actions/verify` | Run 12-check verification, append to MMR, emit evidence |
| `POST` | `/actions/execute-demo` | Combined verify + execute for demo agents |
| `GET` | `/audit` | List verification records |
| `GET` | `/audit/root` | MMR root hash + integrity status |
| `POST` | `/audit/verify-proof` | Manually verify an MMR inclusion proof |
| `GET` | `/evidence/{id}` | Full evidence record with MMR proof |
| `GET` | `/evidence/{id}/pdf` | Downloadable PDF evidence report |
| `GET` | `/evidence/{id}/proof` | Raw MMR proof fields only |
| `GET` | `/metrics` | Aggregate counters: allowed, blocked, by risk category |

## OWASP Coverage

| Risk | Coverage | How |
|------|----------|-----|
| LLM01 | Full | `scan_for_injection()` at intent creation + re-scan at verify check 10 |
| LLM05 | Full | Output schema declared at registration; `validate_output_schema()` at verify check 9 |
| LLM06 | Full | 12-check cryptographic verification cycle — payload hash, signature, JTI, scope |
| LLM10 | Full | Per-agent hourly action limits + daily budget caps enforced at policy evaluation |
| LLM02–04, 07–09 | Out of scope | See [docs/OWASP_COVERAGE.md](docs/OWASP_COVERAGE.md) |

## Research Foundation

This gateway implements the LICITRA framework:

- **LICITRA-SENTRY** — pre-execution enforcement layer: [https://doi.org/10.5281/zenodo.18860290](https://doi.org/10.5281/zenodo.18860290)
- **LICITRA-MMR-CORE** — tamper-evident MMR audit chain: [https://doi.org/10.5281/zenodo.18843032](https://doi.org/10.5281/zenodo.18843032)

## Test Suite

81+ unit tests covering all 7 packages.

```bash
make test
```

## License

MIT