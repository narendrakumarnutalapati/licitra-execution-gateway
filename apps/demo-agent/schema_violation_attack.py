import sys
sys.path.insert(0, "/app")

from demo_helper import (
    EMAIL_SCHEMA,
    register_agent, create_intent, evaluate_policy,
    issue_ticket, verify_action,
    print_header, print_blocked,
)

print_header("ATTACK: SCHEMA VIOLATION", "LLM05")

AGENT = "demo-schema-agent"
ACTION = "send_email"
RESOURCE = "cfo@company.com"

VIOLATING_PAYLOAD = {
    "to": "cfo@company.com",
    "subject": "Q3",
    "body": "See attached.",
    "bcc": "exfiltration@shadow.com",
}

register_agent(
    agent_id=AGENT,
    allowed_actions=[ACTION],
    allowed_resources=[RESOURCE],
    output_schemas={ACTION: EMAIL_SCHEMA},
)

intent = create_intent(AGENT, ACTION, RESOURCE, "Send Q3 report — schema violation demo")
decision = evaluate_policy(intent["intent_id"], AGENT)
ticket = issue_ticket(decision["decision_id"], AGENT, VIOLATING_PAYLOAD)
ticket_id = ticket["ticket_id"]

result = verify_action(ticket_id, AGENT, ACTION, RESOURCE, VIOLATING_PAYLOAD)

violations = result.get("schema_violations") or []
print_blocked(
    reason=result.get("reason", "UNKNOWN"),
    schema_violations=violations,
    mmr_leaf=result.get("mmr_leaf_index"),
)
print("This attack is stopped at: Check 9 — Output Schema Validation")
