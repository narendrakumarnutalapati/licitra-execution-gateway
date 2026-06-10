import time

from packages.tickets.tickets import generate_keypair


EMAIL_SCHEMA = {
    "type": "object",
    "required": ["to", "subject", "body"],
    "properties": {
        "to": {"type": "string"},
        "subject": {"type": "string"},
        "body": {"type": "string"},
    },
    "additionalProperties": False,
}


def _agent_body(suffix=None):
    kp = generate_keypair()
    agent_id = f"reg-agent-{suffix or int(time.time() * 1000)}"
    return {
        "agent_id": agent_id,
        "agent_name": "Registration Test Agent",
        "public_key": kp["public_key_hex"],
        "owner": "integration-test",
        "allowed_actions": ["send_email"],
        "allowed_resources": ["cfo@company.com"],
        "output_schemas": {},
        "max_actions_per_hour": 100,
        "max_actions_per_day": 500,
        "max_daily_budget": 100.0,
        "action_cost_weights": {"send_email": 1.0},
    }


def test_register_agent_success(client):
    body = _agent_body()
    r = client.post("/agents/register", json=body)
    assert r.status_code == 201
    assert r.json()["registered"] is True


def test_register_agent_returns_fingerprint(client):
    body = _agent_body()
    r = client.post("/agents/register", json=body)
    assert r.status_code == 201
    assert "public_key_fingerprint" in r.json()
    assert len(r.json()["public_key_fingerprint"]) == 64


def test_register_duplicate_agent_fails(client):
    body = _agent_body()
    r1 = client.post("/agents/register", json=body)
    assert r1.status_code == 201
    r2 = client.post("/agents/register", json=body)
    assert r2.status_code == 409


def test_register_agent_with_output_schema(client):
    body = _agent_body()
    body["output_schemas"] = {"send_email": EMAIL_SCHEMA}
    r = client.post("/agents/register", json=body)
    assert r.status_code == 201
    assert r.json()["registered"] is True


def test_register_agent_missing_field_fails(client):
    kp = generate_keypair()
    body = {
        "agent_id": f"missing-name-{int(time.time() * 1000)}",
        "public_key": kp["public_key_hex"],
        "owner": "integration-test",
        "allowed_actions": ["send_email"],
        "allowed_resources": ["cfo@company.com"],
        "output_schemas": {},
        "max_actions_per_hour": 100,
        "max_actions_per_day": 500,
        "max_daily_budget": 100.0,
        "action_cost_weights": {},
    }
    r = client.post("/agents/register", json=body)
    assert r.status_code == 422
