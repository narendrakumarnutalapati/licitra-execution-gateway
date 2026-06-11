# LICITRA Competitive Positioning

## Architecture Statement
"Okta/Silverfort/Multifactor identify the actor. Microsoft AGT/Cerbos/TealTiger enforce runtime policy. Clawvisor/Aembit vault credentials. OPAQUE attests the environment. LICITRA proves the exact action was authorized, untampered, replay-resistant, and executed as approved — and produces an MMR inclusion proof any third party can verify independently."

## Competitor Map
Last updated: June 2026. Four new entrants added
(Certiv, Crittora, updated Microsoft AGT, updated
CodeIntegrity) reflecting the rapid evolution of
the agentic AI security market in Q1-Q2 2026.

### Microsoft Agent Governance Toolkit (AGT)
Released: April 2, 2026 | Open Source | MIT License | Production
GitHub: github.com/microsoft/agent-governance-toolkit
Publicly emphasises: Policy enforcement at sub-0.1ms,
Ed25519 cryptographic agent identity (SPIFFE/DID/mTLS),
execution sandboxing (4-tier privilege rings), all 10
OWASP Agentic AI risks, 12+ framework integrations
(LangChain, CrewAI, AutoGen, Google ADK, OpenAI Agents),
Python/TypeScript/Rust/Go/.NET SDKs, 992 conformance
tests, tamper-evident audit log
Does not publicly address: Cryptographic binding of
approved payload hash to executing action,
JTI-based replay prevention at verification layer,
MMR inclusion proofs verifiable by third parties
without trusting the operator, field-level diff
between approved and executed payload
LICITRA relationship: Microsoft AGT is the most
capable competitor in production. AGT gates access,
enforces policy, and establishes cryptographic
agent identity. LICITRA runs after AGT.
AGT answers: is this agent allowed to do this?
LICITRA answers: did the action that executed match
byte-for-byte what was approved, and can a regulator
prove it independently?
A serious compliance deployment needs both layers.

### OPAQUE (UC Berkeley RISELab)
Stage: Series A $24M | Enterprise customers: ServiceNow, Anthropic, Accenture | Production
Publicly emphasises: Hardware TEE attestation, verifiable governance
Does not publicly address: Application-layer ticket binding, MMR inclusion proofs
LICITRA relationship: OPAQUE proves the environment. LICITRA proves the specific action inside it.

### Clawvisor (YC Spring 2026)
Stage: Early — explicitly experimental, not security-audited
Publicly emphasises: Credential vaulting, task approval, audit log
Does not publicly address: Payload hash binding, replay protection, MMR proofs
LICITRA relationship: Clawvisor hides secrets. LICITRA proves what was done with them.

### Multifactor (YC 2026)
Stage: Early — enterprise pilots only
Publicly emphasises: Auth/authz for agentic systems, event history
Does not publicly address: Execution integrity, MMR audit chain
LICITRA relationship: Multifactor identifies the agent. LICITRA proves the agent's action was untampered.

### Cerbos
Stage: Growth | $11M raised | $1.6M revenue | Production
Publicly emphasises: Policy decisions, sub-1ms, open-source, 4300+ GitHub stars
Does not publicly address: Execution-level proof, MMR audit chain
LICITRA relationship: Cerbos makes the allow/deny call. LICITRA binds that decision cryptographically to execution.

### TealTiger
Publicly emphasises: Runtime governance, workload identity, signed audit receipts
Does not publicly address: Action-payload binding at execution level
LICITRA relationship: TealTiger governs at workflow level. LICITRA proves at action level.

### CodeIntegrity
Stage: $5M seed raised May 27 2026 |
Enterprise pilots — broader rollout planned
Publicly emphasises: Full visibility into runtime
tool actions, Zero Trust Control Plane for agent
execution, data provenance tracking, intent evaluation
before tool calls, MCP security, data flow controls,
compliance evidence generation
Does not publicly address: Ed25519 signed execution
tickets binding payload hash to approved action,
JTI replay prevention, MMR tamper-evident audit chain,
O(log N) inclusion proofs verifiable by third party
Most similar surface area to LICITRA of all competitors.
LICITRA relationship: CodeIntegrity approaches the
problem from a data-loss-prevention and visibility
angle. LICITRA approaches it from a cryptographic
integrity angle. CodeIntegrity tracks what data flows
where. LICITRA proves the exact payload that executed
matched the exact payload that was approved, with
a tamper-evident proof chain a regulator can verify
independently.

### Certiv
Stage: Pre-seed $4.2M raised March 2026 |
Pilots only — not publicly available
Publicly emphasises: Runtime assurance for AI agents,
endpoint-native interception on Windows/Mac/Linux,
shadow agent discovery, pre-execution policy enforcement,
OWASP Agentic 2026 coverage, intent-based policies
Does not publicly address: Cryptographic payload hash
binding between approval and execution, JTI replay
prevention, MMR tamper-evident audit chain,
third-party verifiable inclusion proofs
LICITRA relationship: Certiv sits on the endpoint
machine where the agent runs. LICITRA sits between
the agent and the tool API. Different architectural
layers. Certiv governs agent behaviour at the OS
level. LICITRA proves the exact payload that reached
the tool matched what was cryptographically approved.

### Crittora / OpenClaw
Stage: Early — request-access only, announced
February 2026
Publicly emphasises: Cryptographically enforced
policy framework for the OpenClaw agent runtime,
prevention of privilege escalation, configuration
drift protection, audit-ready policy integrity
Does not publicly address: Per-action payload hash
binding (listed as future feature), JTI replay
prevention, MMR inclusion proofs, framework-agnostic
deployment
LICITRA relationship: Crittora is runtime-specific
to OpenClaw. LICITRA is framework-agnostic.
Crittora's per-action execution authorization is
a roadmap item. LICITRA implements it today.

## LICITRA Defensible Moat
Based on publicly available documentation as of June 2026, no competitor publicly describes all four in combination:
1. Signed execution ticket binding approved payload hash to executing action
2. JTI-based replay attack prevention at action verification layer
3. Verification Diff Engine showing field-level differences between approved and executed
4. Tamper-evident MMR evidence chain with O(log N) inclusion proofs verifiable by third party

## Known Limitations (v1.0)

The current gateway operates as a single-operator system.
Tamper-evidence in v1.0 requires trusting the operator
not to modify the PostgreSQL database and MMR state.
The `mmr_detect_tampering()` function detects modifications
after the fact but cannot prevent a compromised operator
from replacing both the event data and the stored hashes
simultaneously.

The witnessed transparency layer described in
LICITRA-SENTRY v0.2 would address this by requiring
external witness co-signatures on epoch root hashes.
This is planned for v2.0.

## Regulatory Tailwind
- EU AI Act high-risk obligations: August 2026
- Colorado AI Act: June 2026 — enforceable now
- LICITRA evidence chain is a direct compliance artifact at action level