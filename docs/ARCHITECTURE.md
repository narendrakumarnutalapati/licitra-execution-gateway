# LICITRA Execution Gateway — Architecture

## System Overview

```
[AI Agent]
|
v
POST /intent/create
|
[packages/intent]
|- scan_for_injection() [LLM01]
|- canonicalize_intent()
|- hash_intent()
|
v
POST /policy/evaluate
|
[packages/policy]
|- evaluate_policy()
|- check_rate_limit() [LLM10] SELECT FOR UPDATE
|- check_budget() [LLM10] SELECT FOR UPDATE
|
v
POST /tickets/issue
|
[packages/tickets]
|- issue_execution_ticket()
|- sign_ticket() Ed25519
|- calculate_payload_hash()
|
v
POST /actions/verify
|
[packages/verifier]
|- 12 checks in order
|- validate_output_schema() [LLM05]
|- scan_for_injection() re-scan [LLM01]
|- verification_diff()
|
v
POST /actions/execute-demo
|
[packages/audit_chain]
|- append_audit_event()
|
[packages/mmr]
|- mmr_append() -> leaf_index, proof, root
|
[packages/evidence]
|- generate_evidence_json()
|- generate_evidence_pdf()
```

## Component Map

| Package | Responsibility | OWASP |
|---|---|---|
| packages/intent | Intent creation + injection scanning | LLM01 |
| packages/policy | Policy evaluation + rate limiting + budget | LLM10 |
| packages/tickets | Ed25519 ticket issuance + signature | LLM06 |
| packages/verifier | 12-check verification + diff + schema | LLM05 LLM06 |
| packages/mmr | Merkle Mountain Range audit chain | LLM06 |
| packages/audit_chain | Event append + integrity check | LLM06 |
| packages/evidence | JSON + PDF evidence generation | LLM06 |

## Database Schema

### agents
```sql
agent_id UUID PRIMARY KEY
agent_name VARCHAR(255) NOT NULL
public_key TEXT NOT NULL
owner VARCHAR(255) NOT NULL
allowed_actions JSONB NOT NULL DEFAULT '[]'
allowed_resources JSONB NOT NULL DEFAULT '[]'
output_schemas JSONB NOT NULL DEFAULT '{}'
max_actions_per_hour INTEGER NOT NULL DEFAULT 100
max_actions_per_day INTEGER NOT NULL DEFAULT 500
max_daily_budget NUMERIC(10,4) NOT NULL DEFAULT 100.0
action_cost_weights JSONB NOT NULL DEFAULT '{}'
is_active BOOLEAN NOT NULL DEFAULT TRUE
registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
```

### intents
```sql
intent_id UUID PRIMARY KEY
user_id VARCHAR(255) NOT NULL
agent_id UUID REFERENCES agents
action VARCHAR(255) NOT NULL
resource TEXT NOT NULL
purpose TEXT NOT NULL
constraints JSONB NOT NULL DEFAULT '{}'
expires_at TIMESTAMPTZ NOT NULL
injection_scan_result VARCHAR(50) NOT NULL DEFAULT 'PASS'
injection_patterns_found JSONB DEFAULT NULL
status VARCHAR(50) NOT NULL DEFAULT 'PENDING'
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
```

### policy_decisions
```sql
decision_id UUID PRIMARY KEY
intent_id UUID REFERENCES intents
agent_id UUID REFERENCES agents
allowed BOOLEAN NOT NULL
reason TEXT NOT NULL
policy_hash VARCHAR(64) NOT NULL
rate_limit_check VARCHAR(50) NOT NULL DEFAULT 'PASS'
budget_check VARCHAR(50) NOT NULL DEFAULT 'PASS'
current_hourly_count INTEGER NOT NULL DEFAULT 0
current_daily_count INTEGER NOT NULL DEFAULT 0
current_daily_cost NUMERIC(10,4) NOT NULL DEFAULT 0
evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
```

### execution_tickets
```sql
ticket_id UUID PRIMARY KEY
decision_id UUID REFERENCES policy_decisions
agent_id UUID REFERENCES agents
action VARCHAR(255) NOT NULL
resource TEXT NOT NULL
purpose TEXT NOT NULL
constraints_hash VARCHAR(64) NOT NULL
payload_hash VARCHAR(64) NOT NULL
output_schema_hash VARCHAR(64) NOT NULL
expires_at TIMESTAMPTZ NOT NULL
jti UUID UNIQUE NOT NULL
issuer_signature TEXT NOT NULL
status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE'
issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
```

### agent_rate_counters
```sql
counter_id UUID PRIMARY KEY
agent_id UUID REFERENCES agents NOT NULL
action VARCHAR(255) NOT NULL
window_start TIMESTAMPTZ NOT NULL
hourly_count INTEGER NOT NULL DEFAULT 0
daily_count INTEGER NOT NULL DEFAULT 0
daily_cost NUMERIC(10,4) NOT NULL DEFAULT 0.0
last_action_at TIMESTAMPTZ DEFAULT NULL
```

### verification_records
```sql
record_id UUID PRIMARY KEY
ticket_id UUID REFERENCES execution_tickets
agent_id UUID REFERENCES agents
action_submitted VARCHAR(255) NOT NULL
resource_submitted TEXT NOT NULL
payload_hash_submitted VARCHAR(64) NOT NULL
allowed BOOLEAN NOT NULL
reason VARCHAR(255) NOT NULL
checks_passed JSONB NOT NULL
diff JSONB DEFAULT NULL
schema_violations JSONB DEFAULT NULL
injection_recheck VARCHAR(50) NOT NULL DEFAULT 'PASS'
evidence_id UUID NOT NULL
verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
```

### mmr_leaves
```sql
leaf_id UUID PRIMARY KEY
leaf_index BIGINT UNIQUE NOT NULL
leaf_hash VARCHAR(64) NOT NULL
event_type VARCHAR(100) NOT NULL
event_data JSONB NOT NULL
proof JSONB NOT NULL
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
```

### mmr_peaks
```sql
peak_id UUID PRIMARY KEY
height INTEGER NOT NULL
position BIGINT NOT NULL
hash VARCHAR(64) NOT NULL
updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
```

### evidence
```sql
evidence_id UUID PRIMARY KEY
intent_id UUID NOT NULL
decision_id UUID NOT NULL
ticket_id UUID NOT NULL
agent_id UUID NOT NULL
action VARCHAR(255) NOT NULL
resource TEXT NOT NULL
decision VARCHAR(50) NOT NULL
reason TEXT NOT NULL
diff JSONB DEFAULT NULL
schema_violations JSONB DEFAULT NULL
injection_findings JSONB DEFAULT NULL
payload_hash VARCHAR(64) NOT NULL
ticket_hash VARCHAR(64) NOT NULL
mmr_leaf_index BIGINT NOT NULL
mmr_leaf_hash VARCHAR(64) NOT NULL
mmr_root VARCHAR(64) NOT NULL
mmr_proof JSONB NOT NULL
mmr_proof_size INTEGER NOT NULL
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
```

### metrics_snapshots
```sql
snapshot_id UUID PRIMARY KEY
snapshot_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
total_verifications INTEGER NOT NULL DEFAULT 0
allowed_count INTEGER NOT NULL DEFAULT 0
blocked_count INTEGER NOT NULL DEFAULT 0
injection_blocks INTEGER NOT NULL DEFAULT 0
schema_blocks INTEGER NOT NULL DEFAULT 0
rate_limit_blocks INTEGER NOT NULL DEFAULT 0
mmr_leaf_count INTEGER NOT NULL DEFAULT 0
mmr_root VARCHAR(64) NOT NULL DEFAULT ''
```

## Technology Stack
- Backend: Python 3.12 + FastAPI + Uvicorn
- Database: PostgreSQL + SQLAlchemy + Alembic
- Crypto: Ed25519 via PyNaCl
- Hashing: SHA-256 via hashlib
- Schema Validation: jsonschema
- PDF Generation: ReportLab
- Testing: pytest + httpx
- Container: Docker + Docker Compose
- Frontend: React + Vite

