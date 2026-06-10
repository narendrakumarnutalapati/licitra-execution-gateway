import sys
sys.path.insert(0, "/app")

from demo_helper import (
    EMAIL_SCHEMA,
    register_agent, create_intent, evaluate_policy,
    issue_ticket, verify_action,
    print_header, print_blocked,
)

print_header("ATTACK: TAMPERED PAYLOAD", "LLM06")

AGENT = "demo-tamper-agent"
ACTION = "send_email"
RESOURCE = "cfo@company.com"

APPROVED_PAYLOAD = {"to": "cfo@company.com", "subject": "Q3 Report", "body": "See attached."}
TAMPERED_PAYLOAD = {"to": "attacker@evil.com", "subject": "Q3 Report", "body": "See attached."}

register_agent(
    agent_id=AGENT,
    allowed_actions=[ACTION],
    allowed_resources=[RESOURCE],
    output_schemas={ACTION: EMAIL_SCHEMA},
)

intent = create_intent(AGENT, ACTION, RESOURCE, "Send Q3 report to CFO")
decision = evaluate_policy(intent["intent_id"], AGENT)
ticket = issue_ticket(decision["decision_id"], AGENT, APPROVED_PAYLOAD)
ticket_id = ticket["ticket_id"]

result = verify_action(ticket_id, AGENT, ACTION, RESOURCE, TAMPERED_PAYLOAD)

print_blocked(
    reason=result.get("reason", "UNKNOWN"),
    diff=result.get("diff"),
    mmr_leaf=result.get("mmr_leaf_index"),
)
print("This attack is stopped at: Check 8 — Payload Hash Verification")
