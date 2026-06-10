# LICITRA Execution Gateway — Product Requirements Document

## Product Mission
LICITRA Execution Gateway is a cryptographic execution integrity layer for AI agents. It proves that every AI agent action was authorized, untampered, replay-resistant, and executed as approved.

LICITRA is NOT a governance platform. It is NOT an identity platform. It is NOT a monitoring tool. It is the missing layer between policy approval and tool execution.

## Core Problem
Most AI agent security tools answer: "Is this agent allowed to do this?"
LICITRA answers: "Did the action that actually executed match — byte for byte — what was approved?"

## Core Flow
Intent (LLM01 injection scan) → Policy (LLM10 rate limiting) → Signed Ed25519 Ticket → 12-check Verification (LLM05 schema + LLM01 re-scan) → MMR Audit Append → Tamper-Evident Evidence

## Users
- AI agent developers integrating execution controls
- Security engineers auditing agent behavior
- Compliance officers needing regulatory evidence
- External auditors verifying agent action history

## Functional Requirements

### FR-01 Intent Creation
- Accept intent from agent with action, resource, purpose, constraints
- Run injection scan (LLM01) on all string fields before any processing
- Block and log intent if injection detected
- Store intent with scan result

### FR-02 Policy Evaluation
- Deny by default
- Check allowed_actions and allowed_resources per agent
- Enforce hourly and daily rate limits (LLM10)
- Enforce daily budget caps (LLM10)
- Return decision_id, allowed, reason, policy_hash

### FR-03 Ticket Issuance
- Issue Ed25519-signed execution ticket only if policy allows
- Bind exact payload hash, action, resource, constraints_hash, output_schema_hash
- Include jti (UUID) for replay prevention
- Set expiry maximum 15 minutes from issuance

### FR-04 Verification (12 checks)
1. Agent registered and active
2. Ticket exists
3. Ed25519 signature valid
4. Ticket not expired
5. JTI not replayed (SELECT FOR UPDATE)
6. Action matches exactly
7. Resource matches exactly
8. Payload hash matches
9. Output schema valid (LLM05)
10. Injection re-scan on payload (LLM01)
11. Agent scope check
12. Decision binding valid

### FR-05 MMR Audit Chain
- Append every event (allowed and blocked) to Merkle Mountain Range
- Bind leaf_index into leaf_hash to prevent position-swap attacks
- Store inclusion proof at insert time
- Support independent third-party verification via inclusion proof

### FR-06 Evidence Generation
- Generate JSON evidence with all fields including MMR proof
- Generate PDF evidence with diff section, OWASP finding, MMR section
- Support POST /audit/verify-proof with no database access required

## Non-Functional Requirements
- Verification response under 200ms for standard checks
- MMR append under 50ms
- Postgres with SELECT FOR UPDATE for all counter operations
- All timestamps UTC ISO-8601
- All hashes SHA-256 hex 64 characters

## Out of Scope
- Identity management (use Okta, Silverfort, Multifactor)
- Runtime policy governance (use Microsoft AGT, Cerbos)
- Credential vaulting (use Clawvisor, Aembit)
- Environment attestation (use OPAQUE)
- LLM02, LLM03, LLM04, LLM07, LLM08, LLM09