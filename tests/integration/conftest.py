import time
from datetime import datetime, timezone, timedelta

import httpx
import pytest

from packages.tickets.tickets import generate_keypair, issue_execution_ticket

BASE = "http://localhost:8000"

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


@pytest.fixture
def client():
    with httpx.Client(base_url=BASE, timeout=15) as c:
        yield c


@pytest.fixture
def registered_agent(client):
    agent_id = f"test-agent-{int(time.time() * 1000)}"
    kp = generate_keypair()
    body = {
        "agent_id": agent_id,
        "agent_name": f"Test Agent {agent_id}",
        "public_key": kp["public_key_hex"],
        "owner": "integration-test",
        "allowed_actions": ["send_email", "read_email"],
        "allowed_resources": ["cfo@company.com", "inbox/*"],
        "output_schemas": {"send_email": EMAIL_SCHEMA},
        "max_actions_per_hour": 100,
        "max_actions_per_day": 500,
        "max_daily_budget": 100.0,
        "action_cost_weights": {"send_email": 1.0, "read_email": 1.0},
    }
    r = client.post("/agents/register", json=body)
    assert r.status_code == 201, f"Agent registration failed: {r.text}"
    return {
        "agent_id": agent_id,
        "keypair": kp,
        "schema": EMAIL_SCHEMA,
    }


@pytest.fixture
def full_flow(client, registered_agent):
    agent_id = registered_agent["agent_id"]
    kp = registered_agent["keypair"]
    payload = {"to": "cfo@company.com", "subject": "Q3 Report", "body": "See attached."}
    expires = _expires(30)

    r = client.post("/intent/create", json={
        "user_id": "integration-test",
        "agent_id": agent_id,
        "action": "send_email",
        "resource": "cfo@company.com",
        "purpose": "Send quarterly report",
        "constraints": {},
        "expires_at": expires,
    })
    assert r.status_code == 201
    intent_id = r.json()["intent_id"]

    r = client.post("/policy/evaluate", json={
        "agent_id": agent_id,
        "intent_id": intent_id,
    })
    assert r.status_code == 200
    pol = r.json()
    assert pol["allowed"], f"Policy blocked: {pol.get('reason')}"
    decision_id = pol["decision_id"]

    r = client.post("/tickets/issue", json={
        "decision_id": decision_id,
        "agent_id": agent_id,
        "action": "send_email",
        "resource": "cfo@company.com",
        "purpose": "Send quarterly report",
        "constraints": {},
        "payload": payload,
        "expires_at": expires,
    })
    assert r.status_code == 201
    ticket_id = r.json()["ticket_id"]

    r = client.post("/actions/verify", json={
        "ticket_id": ticket_id,
        "agent_id": agent_id,
        "action": "send_email",
        "resource": "cfo@company.com",
        "payload": payload,
    })
    assert r.status_code == 200
    return r.json()
