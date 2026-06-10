import sys
sys.path.insert(0, "/app")
sys.path.insert(0, "/app/apps/demo-agent")

from demo_helper import (
    EMAIL_SCHEMA,
    register_agent, create_intent, evaluate_policy,
    issue_ticket, verify_action,
    print_header, print_allowed, print_blocked,
)

print_header("GMAIL USE CASE")

AGENT = "demo-gmail-agent"
SEND_ACTION = "send_email"
READ_ACTION = "read_email"
RESOURCE = "gmail/narendra"

register_agent(
    agent_id=AGENT,
    allowed_actions=[SEND_ACTION, READ_ACTION],
    allowed_resources=[RESOURCE, "cfo@company.com"],
    output_schemas={SEND_ACTION: EMAIL_SCHEMA},
    action_cost_weights={SEND_ACTION: 1.0, READ_ACTION: 0.2},
)

print("\n--- Scenario 1: Authorized email send ---")
valid_payload = {"to": "cfo@company.com", "subject": "Q3 Financial Report", "body": "Please find attached."}
intent = create_intent(AGENT, SEND_ACTION, "cfo@company.com", "Send Q3 report to CFO")
decision = evaluate_policy(intent["intent_id"], AGENT)
ticket = issue_ticket(decision["decision_id"], AGENT, valid_payload)
result = verify_action(ticket["ticket_id"], AGENT, SEND_ACTION, "cfo@company.com", valid_payload)
if result.get("allowed"):
    print_allowed(result["evidence_id"], result["mmr_leaf_index"], result["mmr_root"])
else:
    print(f"UNEXPECTED BLOCK: {result.get('reason')}")

print("\n--- Scenario 2: Schema violation (add bcc field) ---")
violating_payload = {
    "to": "cfo@company.com",
    "subject": "Q3 Financial Report",
    "body": "Please find attached.",
    "bcc": "exfiltration@shadow.com",
}
intent2 = create_intent(AGENT, SEND_ACTION, "cfo@company.com", "Send Q3 report with bcc")
decision2 = evaluate_policy(intent2["intent_id"], AGENT)
ticket2 = issue_ticket(decision2["decision_id"], AGENT, violating_payload)
result2 = verify_action(ticket2["ticket_id"], AGENT, SEND_ACTION, "cfo@company.com", violating_payload)
if not result2.get("allowed"):
    violations = result2.get("schema_violations") or []
    print_blocked(
        reason=result2.get("reason", "UNKNOWN"),
        schema_violations=violations,
        mmr_leaf=result2.get("mmr_leaf_index"),
    )
else:
    print("UNEXPECTED ALLOW (schema violation not blocked)")
