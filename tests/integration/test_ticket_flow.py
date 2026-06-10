from datetime import datetime, timezone, timedelta


def _expires(minutes: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def _issue_ticket(client, registered_agent):
    agent_id = registered_agent["agent_id"]
    expires = _expires(30)
    payload = {"to": "cfo@company.com", "subject": "Q3 Report", "body": "See attached."}

    r = client.post("/intent/create", json={
        "user_id": "integration-test",
        "agent_id": agent_id,
        "action": "send_email",
        "resource": "cfo@company.com",
        "purpose": "Ticket flow test",
        "constraints": {},
        "expires_at": expires,
    })
    assert r.status_code == 201
    intent_id = r.json()["intent_id"]

    r = client.post("/policy/evaluate", json={"agent_id": agent_id, "intent_id": intent_id})
    assert r.status_code == 200
    decision_id = r.json()["decision_id"]

    r = client.post("/tickets/issue", json={
        "decision_id": decision_id,
        "agent_id": agent_id,
        "action": "send_email",
        "resource": "cfo@company.com",
        "purpose": "Ticket flow test",
        "constraints": {},
        "payload": payload,
        "expires_at": expires,
    })
    assert r.status_code == 201
    return r.json()


def test_issue_ticket_success(client, registered_agent):
    ticket = _issue_ticket(client, registered_agent)
    assert "ticket_id" in ticket
    assert ticket["ticket_id"]


def test_ticket_has_issuer_signature(client, registered_agent):
    ticket = _issue_ticket(client, registered_agent)
    assert "issuer_signature" in ticket
    assert ticket["issuer_signature"]


def test_ticket_has_correct_agent_id(client, registered_agent):
    ticket = _issue_ticket(client, registered_agent)
    assert ticket["agent_id"] == registered_agent["agent_id"]


def test_ticket_has_payload_hash(client, registered_agent):
    ticket = _issue_ticket(client, registered_agent)
    assert "payload_hash" in ticket
    assert ticket["payload_hash"]
