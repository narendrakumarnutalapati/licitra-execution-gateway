import time
from datetime import datetime, timezone, timedelta

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


def _expires(minutes: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def _register(client, agent_id, output_schemas=None, max_actions_per_hour=100):
    kp = generate_keypair()
    client.post("/agents/register", json={
        "agent_id": agent_id,
        "agent_name": f"Verify Test {agent_id}",
        "public_key": kp["public_key_hex"],
        "owner": "integration-test",
        "allowed_actions": ["send_email", "read_email"],
        "allowed_resources": ["cfo@company.com", "inbox/*"],
        "output_schemas": output_schemas or {"send_email": EMAIL_SCHEMA},
        "max_actions_per_hour": max_actions_per_hour,
        "max_actions_per_day": 500,
        "max_daily_budget": 100.0,
        "action_cost_weights": {"send_email": 1.0, "read_email": 1.0},
    })


def _run_flow(client, agent_id, action="send_email", resource="cfo@company.com",
              payload=None, expires_minutes=30, verify_action=None,
              verify_resource=None, verify_payload=None):
    if payload is None:
        payload = {"to": "cfo@company.com", "subject": "Q3 Report", "body": "See attached."}
    expires = _expires(expires_minutes)

    r = client.post("/intent/create", json={
        "user_id": "integration-test",
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "purpose": "Verify flow test",
        "constraints": {},
        "expires_at": expires,
    })
    assert r.status_code == 201, r.text
    data = r.json()
    if data.get("status") == "INJECTION_BLOCKED":
        return None, None
    intent_id = data["intent_id"]

    r = client.post("/policy/evaluate", json={"agent_id": agent_id, "intent_id": intent_id})
    assert r.status_code == 200, r.text
    pol = r.json()
    if not pol["allowed"]:
        return None, None
    decision_id = pol["decision_id"]

    r = client.post("/tickets/issue", json={
        "decision_id": decision_id,
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "purpose": "Verify flow test",
        "constraints": {},
        "payload": payload,
        "expires_at": expires,
    })
    assert r.status_code == 201, r.text
    ticket_id = r.json()["ticket_id"]

    r = client.post("/actions/verify", json={
        "ticket_id": ticket_id,
        "agent_id": agent_id,
        "action": verify_action or action,
        "resource": verify_resource or resource,
        "payload": verify_payload or payload,
    })
    assert r.status_code == 200, r.text
    return ticket_id, r.json()


def test_happy_path_all_12_checks_pass(client, registered_agent):
    _, result = _run_flow(client, registered_agent["agent_id"])
    assert result["allowed"] is True
    assert "All 12 checks passed" in result["reason"]


def test_happy_path_returns_evidence_id(client, registered_agent):
    _, result = _run_flow(client, registered_agent["agent_id"])
    assert result["allowed"] is True
    assert "evidence_id" in result
    assert result["evidence_id"]


def test_happy_path_returns_mmr_leaf_index(client, registered_agent):
    _, result = _run_flow(client, registered_agent["agent_id"])
    assert result["allowed"] is True
    assert "mmr_leaf_index" in result
    assert result["mmr_leaf_index"] >= 0


def test_tampered_payload_blocked(client, registered_agent):
    agent_id = registered_agent["agent_id"]
    original_payload = {"to": "cfo@company.com", "subject": "Q3 Report", "body": "See attached."}
    tampered_payload = {"to": "attacker@evil.com", "subject": "Q3 Report", "body": "See attached."}
    _, result = _run_flow(client, agent_id, payload=original_payload,
                          verify_payload=tampered_payload)
    assert result["allowed"] is False
    assert "PAYLOAD_TAMPERED" in result["reason"]


def test_replay_attack_blocked(client, registered_agent):
    agent_id = registered_agent["agent_id"]
    payload = {"to": "cfo@company.com", "subject": "Q3 Report", "body": "See attached."}
    ticket_id, first = _run_flow(client, agent_id, payload=payload)
    assert first["allowed"] is True

    r = client.post("/actions/verify", json={
        "ticket_id": ticket_id,
        "agent_id": agent_id,
        "action": "send_email",
        "resource": "cfo@company.com",
        "payload": payload,
    })
    assert r.status_code == 200
    second = r.json()
    assert second["allowed"] is False
    assert "JTI_REPLAYED" in second["reason"]


def test_expired_ticket_blocked(client, registered_agent):
    agent_id = registered_agent["agent_id"]
    payload = {"to": "cfo@company.com", "subject": "Q3 Report", "body": "See attached."}
    _, result = _run_flow(client, agent_id, payload=payload, expires_minutes=-60)
    assert result["allowed"] is False
    assert "TICKET_EXPIRED" in result["reason"]


def test_schema_violation_blocked(client):
    agent_id = f"schema-vio-{int(time.time() * 1000)}"
    strict_schema = {
        "type": "object",
        "required": ["to", "subject", "body"],
        "properties": {
            "to": {"type": "string"},
            "subject": {"type": "string"},
            "body": {"type": "string"},
        },
        "additionalProperties": False,
    }
    kp = generate_keypair()
    client.post("/agents/register", json={
        "agent_id": agent_id,
        "agent_name": f"Schema Test {agent_id}",
        "public_key": kp["public_key_hex"],
        "owner": "integration-test",
        "allowed_actions": ["send_email"],
        "allowed_resources": ["cfo@company.com"],
        "output_schemas": {"send_email": strict_schema},
        "max_actions_per_hour": 100,
        "max_actions_per_day": 500,
        "max_daily_budget": 100.0,
        "action_cost_weights": {"send_email": 1.0},
    })
    violating_payload = {"to": "cfo@company.com", "subject": "Q3", "body": "OK", "bcc": "exfil@shadow.com"}
    _, result = _run_flow(client, agent_id, payload=violating_payload)
    assert result["allowed"] is False
    assert "OUTPUT_SCHEMA_VIOLATION" in result["reason"]


def test_action_mismatch_blocked(client, registered_agent):
    agent_id = registered_agent["agent_id"]
    payload = {"to": "cfo@company.com", "subject": "Q3 Report", "body": "See attached."}
    _, result = _run_flow(client, agent_id, action="send_email", payload=payload,
                          verify_action="read_email")
    assert result["allowed"] is False
    assert "ACTION_MISMATCH" in result["reason"]
