# LICITRA Competitive Positioning

## Architecture Statement
"Okta/Silverfort/Multifactor identify the actor. Microsoft AGT/Cerbos/TealTiger enforce runtime policy. Clawvisor/Aembit vault credentials. OPAQUE attests the environment. LICITRA proves the exact action was authorized, untampered, replay-resistant, and executed as approved — and produces an MMR inclusion proof any third party can verify independently."

## Competitor Map

### Microsoft Agent Governance Toolkit (AGT)
Released: April 2026 | Open Source | MIT License | Production
Publicly emphasises: Policy enforcement, Ed25519 agent identity, sub-0.1ms latency, all 10 OWASP Agentic AI risks
Does not publicly address: Action-payload binding at execution, MMR inclusion proofs
LICITRA relationship: LICITRA runs after AGT. AGT gates access. LICITRA proves the exact payload was untampered and logs it with MMR proof.

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
Publicly emphasises: Tool-call approvals, execution evidence
Most similar surface area to LICITRA
Does not publicly address: Cryptographic payload binding between approval and execution
LICITRA relationship: CodeIntegrity focuses on approvals and evidence collection. LICITRA adds cryptographic binding proving executed payload = approved payload.

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