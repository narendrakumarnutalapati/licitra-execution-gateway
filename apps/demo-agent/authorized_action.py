import sys, os
sys.path.insert(0, "/app")

from demo_helper import (
    BASE, EMAIL_SCHEMA,
    register_agent, create_intent, evaluate_policy,
    issue_ticket, verify_action, execute_demo,
    print_header, print_allowed,
)

print_header("AUTHORIZED ACTION", "LLM06")

AGENT = "demo-authorized-agent"
ACTION = "send_email"
RESOURCE = "cfo@company.com"
PAYLOAD = {"to": "cfo@company.com", "subject": "Q3 Report", "body": "See attached."}

register_agent(
    agent_id=AGENT,
    allowed_actions=[ACTION],
    allowed_resources=[RESOURCE],
    output_schemas={ACTION: EMAIL_SCHEMA},
    max_actions_per_hour=100,
)

intent = create_intent(AGENT, ACTION, RESOURCE, "Send Q3 financial report")
intent_id = intent["intent_id"]

decision = evaluate_policy(intent_id, AGENT)
decision_id = decision["decision_id"]

ticket = issue_ticket(decision_id, AGENT, PAYLOAD)
ticket_id = ticket["ticket_id"]

result = verify_action(ticket_id, AGENT, ACTION, RESOURCE, PAYLOAD)

if result.get("allowed"):
    print_allowed(result["evidence_id"], result["mmr_leaf_index"], result["mmr_root"])
    exec_result = execute_demo(ticket_id + "-exec", AGENT, ACTION, RESOURCE, PAYLOAD)
else:
    print(f"UNEXPECTED BLOCK: {result.get('reason')}")

print(f"Decision: ALLOWED")
