import httpx

BASE = "http://localhost:8000"

EMAIL_SCHEMA = {
    "type": "object",
    "required": ["to", "subject", "body"],
    "properties": {
        "to": {"type": "string", "format": "email"},
        "subject": {"type": "string", "maxLength": 500},
        "body": {"type": "string"},
    },
    "additionalProperties": False,
}


def register_agent(
    agent_id: str,
    allowed_actions: list,
    allowed_resources: list,
    output_schemas: dict,
    max_actions_per_hour: int = 100,
    max_actions_per_day: int = 500,
    max_daily_budget: float = 100.0,
    action_cost_weights: dict = None,
    owner: str = "demo",
) -> bool:
    if action_cost_weights is None:
        action_cost_weights = {a: 1.0 for a in allowed_actions}

    from packages.tickets.tickets import generate_keypair
    kp = generate_keypair()

    r = httpx.post(f"{BASE}/agents/register", json={
        "agent_id": agent_id,
        "agent_name": agent_id,
        "public_key": kp["public_key_hex"],
        "owner": owner,
        "allowed_actions": allowed_actions,
        "allowed_resources": allowed_resources,
        "output_schemas": output_schemas,
        "max_actions_per_hour": max_actions_per_hour,
        "max_actions_per_day": max_actions_per_day,
        "max_daily_budget": max_daily_budget,
        "action_cost_weights": action_cost_weights,
    })
    return r.json().get("registered", False)


def create_intent(
    agent_id: str,
    action: str,
    resource: str,
    purpose: str,
    constraints: dict = None,
    expires_at: str = "2027-12-31T23:59:59Z",
    user_id: str = "demo-user",
) -> dict:
    r = httpx.post(f"{BASE}/intent/create", json={
        "user_id": user_id,
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "purpose": purpose,
        "constraints": constraints or {},
        "expires_at": expires_at,
    })
    return r.json()


def evaluate_policy(intent_id: str, agent_id: str) -> dict:
    r = httpx.post(f"{BASE}/policy/evaluate", json={
        "intent_id": intent_id,
        "agent_id": agent_id,
    })
    return r.json()


def issue_ticket(decision_id: str, agent_id: str, payload: dict) -> dict:
    r = httpx.post(f"{BASE}/tickets/issue", json={
        "decision_id": decision_id,
        "agent_id": agent_id,
        "payload": payload,
    })
    return r.json()


def verify_action(
    ticket_id: str,
    agent_id: str,
    action: str,
    resource: str,
    payload: dict,
) -> dict:
    r = httpx.post(f"{BASE}/actions/verify", json={
        "ticket_id": ticket_id,
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "payload": payload,
    })
    if r.status_code == 404:
        detail = r.json().get("detail", "not found")
        if "Agent" in detail:
            return {"allowed": False, "reason": "AGENT_NOT_REGISTERED", "checks_passed": {"agent_registered": False}}
        return {"allowed": False, "reason": "TICKET_NOT_FOUND", "checks_passed": {"ticket_exists": False}}
    return r.json()


def execute_demo(
    ticket_id: str,
    agent_id: str,
    action: str,
    resource: str,
    payload: dict,
) -> dict:
    r = httpx.post(f"{BASE}/actions/execute-demo", json={
        "ticket_id": ticket_id,
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "payload": payload,
    })
    return r.json()


def print_header(attack_name: str, owasp_label: str = ""):
    label = f" [{owasp_label}]" if owasp_label else ""
    print(f"\n===== {attack_name}{label} =====")


def print_allowed(evidence_id: str, mmr_leaf: int, mmr_root: str):
    print(f"ALLOWED ✓")
    print(f"Evidence ID: {evidence_id}")
    print(f"MMR leaf index: {mmr_leaf}")
    print(f"MMR root: {mmr_root[:20]}...")


def print_blocked(
    reason: str,
    diff: dict = None,
    schema_violations: list = None,
    injection_findings: list = None,
    mmr_leaf: int = None,
):
    print(f"BLOCKED ✗")
    print(f"Reason: {reason}")
    if diff:
        print("Diff:")
        for k, v in diff.items():
            print(f"  {k}: {v}")
    if schema_violations:
        print(f"Violations: {schema_violations[0] if schema_violations else ''}")
    if injection_findings:
        for f in injection_findings:
            print(f"Pattern matched: {f.get('pattern_id', '')} — {f.get('description', '')}")
            print(f"Risk score: {f.get('risk_score', '')}")
    if mmr_leaf is not None:
        print(f"MMR leaf index: {mmr_leaf}")


def get_mmr_root() -> dict:
    r = httpx.get(f"{BASE}/audit/root")
    return r.json()
