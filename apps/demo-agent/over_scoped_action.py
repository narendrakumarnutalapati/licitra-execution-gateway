import sys
sys.path.insert(0, "/app")

from demo_helper import (
    register_agent, create_intent, evaluate_policy,
    issue_ticket, verify_action,
    print_header, print_blocked,
)

print_header("ATTACK: OVER-SCOPED ACTION", "LLM06")

AGENT = "demo-scope-agent"
APPROVED_ACTION = "read_contact"
ATTEMPTED_ACTION = "delete_contact"
RESOURCE = "contacts/cfo"
PAYLOAD = {"contact_id": "cfo-001"}

register_agent(
    agent_id=AGENT,
    allowed_actions=[APPROVED_ACTION],
    allowed_resources=[RESOURCE],
    output_schemas={APPROVED_ACTION: {"type": "object", "properties": {"contact_id": {"type": "string"}}}},
)

intent = create_intent(AGENT, APPROVED_ACTION, RESOURCE, "Read CFO contact details")
decision = evaluate_policy(intent["intent_id"], AGENT)
ticket = issue_ticket(decision["decision_id"], AGENT, PAYLOAD)
ticket_id = ticket["ticket_id"]

result = verify_action(ticket_id, AGENT, ATTEMPTED_ACTION, RESOURCE, PAYLOAD)

print_blocked(
    reason=result.get("reason", "UNKNOWN"),
    diff=result.get("diff"),
    mmr_leaf=result.get("mmr_leaf_index"),
)
print("This attack is stopped at: Check 6 — Action Binding")
