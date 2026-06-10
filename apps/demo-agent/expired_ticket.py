import sys
sys.path.insert(0, "/app")

from datetime import datetime, timezone, timedelta

from demo_helper import (
    EMAIL_SCHEMA,
    register_agent, create_intent, evaluate_policy,
    issue_ticket, verify_action,
    print_header, print_blocked,
)

print_header("ATTACK: EXPIRED TICKET", "LLM06")

AGENT = "demo-expiry-agent"
ACTION = "send_email"
RESOURCE = "cfo@company.com"
PAYLOAD = {"to": "cfo@company.com", "subject": "Expired Q3", "body": "This ticket is expired."}

register_agent(
    agent_id=AGENT,
    allowed_actions=[ACTION],
    allowed_resources=[RESOURCE],
    output_schemas={ACTION: EMAIL_SCHEMA},
)

past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()

intent = create_intent(
    AGENT, ACTION, RESOURCE,
    "Send expired report",
    expires_at=past,
)
decision = evaluate_policy(intent["intent_id"], AGENT)
ticket = issue_ticket(decision["decision_id"], AGENT, PAYLOAD)
ticket_id = ticket["ticket_id"]

result = verify_action(ticket_id, AGENT, ACTION, RESOURCE, PAYLOAD)

print_blocked(
    reason=result.get("reason", "UNKNOWN"),
    mmr_leaf=result.get("mmr_leaf_index"),
)
print("This attack is stopped at: Check 4 — Ticket Expiry")
