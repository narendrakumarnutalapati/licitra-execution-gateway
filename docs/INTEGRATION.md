# LICITRA Execution Gateway — Integration Guide

## Overview

LICITRA sits between an AI agent and its tools.
It does not replace your existing identity, policy,
or credential infrastructure. It adds execution
integrity on top.

## Integration Pattern

### Step 1 — Register your agent

Call `POST /agents/register` once at agent setup time.
Provide:

- `allowed_actions`: exact list of actions this agent may take
- `allowed_resources`: exact resources (supports wildcards like `crm/contacts/*`)
- `output_schemas`: JSON Schema per action — `additionalProperties: false` recommended
- `max_actions_per_hour`, `max_actions_per_day`, `max_daily_budget`

### Step 2 — Create intent before every action

When the agent decides to take an action, call
`POST /intent/create` with the action, resource,
purpose, and constraints.
LICITRA scans for injection automatically.
If blocked: do not proceed. Log and alert.
If pending: proceed to policy.

### Step 3 — Evaluate policy

Call `POST /policy/evaluate` with `intent_id` and `agent_id`.
If allowed: save `decision_id`.
If denied: do not issue a ticket. Reason is in response.

### Step 4 — Issue execution ticket

Call `POST /tickets/issue` with `decision_id` and the
exact payload the agent will execute.
Save the `ticket_id`.

### Step 5 — Verify before executing

Immediately before the agent calls the tool, call
`POST /actions/verify` with `ticket_id`, `agent_id`,
`action`, `resource`, and the exact payload.
If allowed: execute the tool.
If blocked: do not execute. Log `evidence_id`.

### Step 6 — Store evidence

Every verify call writes an evidence record.
`GET /evidence/{evidence_id}` returns the full record
including MMR inclusion proof.
`GET /evidence/{evidence_id}/pdf` returns a signed PDF.

## Integration with Existing Tools

### With Microsoft AGT

AGT enforces which agents exist and their permissions.
LICITRA proves what each agent actually did.
Run LICITRA verify after AGT policy check passes.

### With Cerbos

Cerbos makes the allow/deny decision.
Pass the Cerbos `decision_id` as your LICITRA intent purpose.
LICITRA binds that decision to the exact payload executed.

### With OPAQUE

OPAQUE attests the environment is trusted.
LICITRA proves the specific action inside that environment
was untampered.
Run LICITRA after OPAQUE attestation passes.

### With MCP (Model Context Protocol)

See [docs/MCP_POSITIONING.md](MCP_POSITIONING.md) for MCP-specific integration.

## Webhook / Event Integration

Poll `GET /audit` for recent events.
Filter by `agent_id` to get per-agent audit trail.
Use `GET /audit/root` to get current MMR root for
external anchoring (e.g. write root hash to
blockchain or external log).

## Evidence for Compliance

Every LICITRA evidence record contains:

- The exact action that was approved
- The exact payload that was submitted for execution
- Whether they matched
- An MMR inclusion proof a third party can verify
  independently using `POST /audit/verify-proof`

This makes LICITRA evidence directly usable for:

- EU AI Act high-risk system audit trails
- Colorado AI Act compliance documentation
- SOC2 Type II evidence collection
- Internal security investigations
