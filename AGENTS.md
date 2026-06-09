# AGENTS.md
Project: LICITRA Execution Gateway
Mission: Cryptographic execution integrity for AI agents.
OWASP LLM01+LLM05+LLM06+LLM10.
Rules:
- Never bypass ticket verification
- Never allow execution without verification
- Deny by default on all policy decisions
- Ed25519 signatures mandatory for all tickets
- JTI replay protection enforced on every verify call using SELECT FOR UPDATE
- scan_for_injection() runs on every intent AND every verify payload re-scan
- validate_output_schema() runs at verify check 9
- check_rate_limit() runs on every policy evaluation using SELECT FOR UPDATE
- check_budget() runs on every policy evaluation using SELECT FOR UPDATE
- increment_counters() called ONLY after confirmed execution never at verify time
- MMR Merkle Mountain Range for audit chain NEVER simple linked chain
- MMR leaf_index MUST be bound into leaf_hash to prevent position-swap attacks
- MMR inclusion proof stored at INSERT time not query time
- Verification diff produced on any value mismatch
- All 12 verification checks run in order first failure terminates
- Every feature has pytest tests minimum 81 total
OWASP: LLM01 scan_for_injection, LLM05 validate_output_schema, LLM06 core, LLM10 rate limiting budget
Stack: FastAPI PostgreSQL React+Vite Ed25519/PyNaCl SHA-256 MMR jsonschema ReportLab pytest Docker