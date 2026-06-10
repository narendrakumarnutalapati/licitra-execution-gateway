# LICITRA Execution Gateway — API Specification

Base URL: http://localhost:8000
All requests: Content-Type: application/json
All timestamps: UTC ISO-8601

---

## GET /healthz
Returns system health including MMR status.

Response 200:
{
  "status": "ok",
  "version": "1.0",
  "mmr_root": "sha256:abc...",
  "mmr_leaves": 47,
  "integrity": "INTACT"
}

---

## POST /agents/register
Register an AI agent with scope, output schemas, and rate limits.

Request:
{
  "agent_id": "uuid",
  "agent_name": "email_agent",
  "public_key": "hex_string",
  "owner": "narendra",
  "allowed_actions": ["send_email"],
  "allowed_resources": ["cfo@company.com"],
  "output_schemas": {
    "send_email": {
      "type": "object",
      "required": ["to", "subject", "body"],
      "properties": {
        "to": {"type": "string", "format": "email"},
        "subject": {"type": "string", "maxLength": 500},
        "body": {"type": "string"}
      },
      "additionalProperties": false
    }
  },
  "max_actions_per_hour": 100,
  "max_actions_per_day": 500,
  "max_daily_budget": 100.0,
  "action_cost_weights": {"send_email": 1.0}
}

Response 200:
{
  "agent_id": "uuid",
  "registered": true,
  "public_key_fingerprint": "sha256:..."
}

Errors:
400: {"error": "AGENT_ALREADY_EXISTS"}
400: {"error": "INVALID_PUBLIC_KEY"}
400: {"error": "INVALID_OUTPUT_SCHEMA"}

---

## POST /intent/create
Create intent. Injection scan runs automatically.

Request:
{
  "user_id": "narendra",
  "agent_id": "uuid",
  "action": "send_email",
  "resource": "cfo@company.com",
  "purpose": "Send Q3 report",
  "constraints": {"max_recipients": 1},
  "expires_at": "2026-06-09T16:00:00Z"
}

Response 200:
{
  "intent_id": "uuid",
  "status": "PENDING",
  "injection_scan": "PASS",
  "created_at": "2026-06-09T14:00:00Z"
}

Response 403 (injection detected):
{
  "error": "INJECTION_DETECTED",
  "patterns_found": [
    {"id": "INJ001", "severity": "HIGH", "matched": "ignore previous instructions"}
  ],
  "intent_id": "uuid",
  "status": "INJECTION_BLOCKED"
}

---

## POST /policy/evaluate
Evaluate intent against agent policy including rate limits and budget.

Request:
{
  "intent_id": "uuid",
  "agent_id": "uuid"
}

Response 200:
{
  "decision_id": "uuid",
  "allowed": true,
  "reason": "All policy checks passed",
  "policy_hash": "sha256:...",
  "rate_limit_check": "PASS",
  "budget_check": "PASS",
  "current_hourly_count": 12,
  "current_daily_count": 47
}

Response 200 (denied):
{
  "decision_id": "uuid",
  "allowed": false,
  "reason": "RATE_LIMIT_EXCEEDED",
  "hourly_count": 100,
  "hourly_limit": 100
}

---

## POST /tickets/issue
Issue signed execution ticket. Only succeeds if policy decision is allowed.

Request:
{
  "decision_id": "uuid",
  "agent_id": "uuid",
  "payload": {
    "to": "cfo@company.com",
    "subject": "Q3 Report",
    "body": "Please find attached..."
  }
}

Response 200:
{
  "ticket_id": "uuid",
  "jti": "uuid",
  "action": "send_email",
  "resource": "cfo@company.com",
  "payload_hash": "sha256:...",
  "output_schema_hash": "sha256:...",
  "expires_at": "2026-06-09T14:15:00Z",
  "issuer_signature": "hex..."
}

Errors:
400: {"error": "POLICY_DECISION_DENIED"}
400: {"error": "DECISION_NOT_FOUND"}

---

## POST /actions/verify
Run all 12 checks. Returns diff on any mismatch. Does not execute.

Request:
{
  "ticket_id": "uuid",
  "agent_id": "uuid",
  "action": "send_email",
  "resource": "cfo@company.com",
  "payload": {
    "to": "cfo@company.com",
    "subject": "Q3 Report",
    "body": "Please find attached..."
  }
}

Response 200 (allowed):
{
  "allowed": true,
  "reason": "All 12 checks passed",
  "checks_passed": {
    "agent_registered": true,
    "ticket_exists": true,
    "signature_valid": true,
    "not_expired": true,
    "jti_not_replayed": true,
    "action_matches": true,
    "resource_matches": true,
    "payload_hash_matches": true,
    "output_schema_valid": true,
    "injection_rescan": true,
    "agent_scope": true,
    "decision_binding": true
  },
  "evidence_id": "uuid",
  "mmr_leaf_index": 47,
  "mmr_proof": ["sha256:...", "sha256:...", "sha256:...", "sha256:..."]
}

Response 200 (blocked):
{
  "allowed": false,
  "reason": "PAYLOAD_TAMPERED",
  "diff": {
    "field": "to",
    "expected_value": "cfo@company.com",
    "actual_value": "attacker@evil.com",
    "mismatch_type": "payload_tampered"
  },
  "evidence_id": "uuid",
  "mmr_leaf_index": 48
}

---

## POST /actions/execute-demo
Mock tool execution. Only executes if verify passes. Increments rate counters after success.

Request: same as /actions/verify

Response 200 (executed):
{
  "executed": true,
  "result": "MOCK_SUCCESS",
  "evidence_id": "uuid",
  "mmr_leaf_index": 47
}

Response 200 (blocked):
{
  "executed": false,
  "reason": "VERIFICATION_FAILED",
  "evidence_id": "uuid"
}

---

## GET /audit
Returns last 50 audit events with MMR leaf indices.

Query params: ?limit=50&offset=0

Response 200:
{
  "events": [
    {
      "leaf_index": 47,
      "event_type": "VERIFY_BLOCKED",
      "agent_id": "uuid",
      "action": "send_email",
      "decision": "BLOCKED",
      "reason": "PAYLOAD_TAMPERED",
      "mmr_leaf_hash": "sha256:...",
      "created_at": "2026-06-09T14:32:01Z"
    }
  ],
  "mmr_root": "sha256:...",
  "total_leaves": 48
}

---

## GET /audit/root
Current MMR root hash and leaf count. Public endpoint. No auth required.

Response 200:
{
  "mmr_root": "sha256:abc...",
  "leaf_count": 48,
  "integrity": "INTACT",
  "last_check": "2026-06-09T14:00:00Z"
}

---

## POST /audit/verify-proof
Verify MMR inclusion proof. Pure hash computation. No database access. Anyone can call.

Request:
{
  "leaf_hash": "sha256:...",
  "proof": ["sha256:...", "sha256:...", "sha256:...", "sha256:..."],
  "root": "sha256:...",
  "leaf_index": 47
}

Response 200 (valid):
{
  "valid": true,
  "leaf_index": 47,
  "proof_size": 4,
  "message": "Event inclusion verified. This event exists in the audit log and is untampered."
}

Response 200 (invalid):
{
  "valid": false,
  "reason": "Root hash mismatch. Provided proof does not verify against provided root."
}

---

## GET /evidence/{id}
Full evidence JSON.

Response 200:
{
  "evidence_id": "uuid",
  "intent_id": "uuid",
  "decision_id": "uuid",
  "ticket_id": "uuid",
  "agent_id": "uuid",
  "action": "send_email",
  "resource": "cfo@company.com",
  "decision": "BLOCKED",
  "reason": "PAYLOAD_TAMPERED",
  "diff": {
    "field": "to",
    "expected_value": "cfo@company.com",
    "actual_value": "attacker@evil.com",
    "mismatch_type": "payload_tampered"
  },
  "schema_violations": null,
  "injection_findings": null,
  "payload_hash": "sha256:...",
  "ticket_hash": "sha256:...",
  "mmr_leaf_index": 47,
  "mmr_leaf_hash": "sha256:...",
  "mmr_root": "sha256:...",
  "mmr_proof": ["sha256:...", "sha256:...", "sha256:...", "sha256:..."],
  "mmr_proof_size": 4,
  "created_at": "2026-06-09T14:32:01Z"
}

---

## GET /evidence/{id}/pdf
Returns PDF evidence report as binary stream.
Content-Type: application/pdf

---

## GET /evidence/{id}/proof
Returns MMR inclusion proof only.

Response 200:
{
  "leaf_hash": "sha256:...",
  "proof": ["sha256:...", "sha256:...", "sha256:...", "sha256:..."],
  "root": "sha256:...",
  "leaf_index": 47
}

---

## GET /metrics
Aggregate counters by verification outcome and attack category.

Response 200:
{
  "total_verifications": 91,
  "allowed_count": 44,
  "blocked_count": 47,
  "injection_blocks": 6,
  "schema_blocks": 4,
  "rate_limit_blocks": 3,
  "replay_blocks": 2,
  "mmr_leaf_count": 91,
  "mmr_root": "sha256:..."
}

---

## POST /metrics/snapshot
Persists current metrics to the metrics_snapshots table. Call to create a point-in-time record.

Response 201:
{
  "snapshot_id": "uuid",
  "snapshot_at": "2026-06-10T20:35:05Z",
  "total_verifications": 91,
  "allowed_count": 44,
  "blocked_count": 47,
  "injection_blocks": 6,
  "schema_blocks": 4,
  "rate_limit_blocks": 3,
  "mmr_leaf_count": 91,
  "mmr_root": "sha256:..."
}

---

## GET /metrics/history
Returns last 10 metrics snapshots ordered by snapshot_at descending.

Response 200: array of snapshot objects (same schema as POST /metrics/snapshot response)

---

## POST /demo/{scenario}
In-process attack/use-case demos for browser UI. All return a structured result object.

Scenarios:
- POST /demo/authorized — authorized action (LLM06)
- POST /demo/tamper — tampered payload (LLM06)
- POST /demo/replay — replay attack (LLM06)
- POST /demo/overscope — over-scoped action (LLM06)
- POST /demo/expired — expired ticket (LLM06)
- POST /demo/fake — fake agent (LLM06)
- POST /demo/injection — prompt injection (LLM01)
- POST /demo/schema — schema violation (LLM05)
- POST /demo/ratelimit — rate limit exceeded (LLM10)
- POST /demo/mmr-tamper — MMR audit chain tampering (LLM06)
- POST /demo/full — runs all scenarios in sequence, returns array

Response 200:
{
  "scenario": "Tampered Payload",
  "owasp": "LLM06",
  "allowed": false,
  "reason": "PAYLOAD_TAMPERED",
  "diff": { "field": "to", "expected_value": "cfo@company.com", "actual_value": "attacker@evil.com" },
  "evidence_id": "uuid",
  "mmr_leaf_index": 47,
  "duration_ms": 12
}