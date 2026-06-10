import time
from datetime import datetime, timezone, timedelta

from packages.tickets.tickets import generate_keypair


def _expires(minutes: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def _register(client, agent_id, allowed_actions, max_actions_per_hour=100):
    kp = generate_keypair()
    client.post("/agents/register", json={
        "agent_id": agent_id,
        "agent_name": f"Policy Test Agent {agent_id}",
        "public_key": kp["public_key_hex"],
        "owner": "integration-test",
        "allowed_actions": allowed_actions,
        "allowed_resources": ["cfo@company.com", "inbox/*"],
        "output_schemas": {},
        "max_actions_per_hour": max_actions_per_hour,
        "max_actions_per_day": 500,
        "max_daily_budget": 100.0,
        "action_cost_weights": {a: 1.0 for a in allowed_actions},
    })


def _create_intent(client, agent_id, action="send_email"):
    r = client.post("/intent/create", json={
        "user_id": "integration-test",
        "agent_id": agent_id,
        "action": action,
        "resource": "cfo@company.com",
        "purpose": "Policy flow test",
        "constraints": {},
        "expires_at": _expires(30),
    })
    assert r.status_code == 201
    return r.json()["intent_id"]


def test_policy_allows_registered_action(client):
    agent_id = f"pol-allow-{int(time.time() * 1000)}"
    _register(client, agent_id, ["send_email"])
    intent_id = _create_intent(client, agent_id, "send_email")
    r = client.post("/policy/evaluate", json={"agent_id": agent_id, "intent_id": intent_id})
    assert r.status_code == 200
    assert r.json()["allowed"] is True


def test_policy_blocks_unregistered_action(client):
    agent_id = f"pol-block-{int(time.time() * 1000)}"
    _register(client, agent_id, ["read_email"])
    intent_id = _create_intent(client, agent_id, "send_email")
    r = client.post("/policy/evaluate", json={"agent_id": agent_id, "intent_id": intent_id})
    assert r.status_code == 200
    assert r.json()["allowed"] is False


def test_policy_returns_decision_id(client):
    agent_id = f"pol-decid-{int(time.time() * 1000)}"
    _register(client, agent_id, ["send_email"])
    intent_id = _create_intent(client, agent_id, "send_email")
    r = client.post("/policy/evaluate", json={"agent_id": agent_id, "intent_id": intent_id})
    assert r.status_code == 200
    assert "decision_id" in r.json()
    assert r.json()["decision_id"]


def test_policy_rate_limit(client):
    agent_id = f"pol-rl-{int(time.time() * 1000)}"
    _register(client, agent_id, ["send_email"], max_actions_per_hour=2)

    results = []
    for _ in range(3):
        intent_id = _create_intent(client, agent_id, "send_email")
        r = client.post("/policy/evaluate", json={"agent_id": agent_id, "intent_id": intent_id})
        assert r.status_code == 200
        results.append(r.json()["allowed"])

    assert results[0] is True
    assert results[1] is True
    assert results[2] is False
