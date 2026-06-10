import sys
sys.path.insert(0, "/app")

from demo_helper import (
    EMAIL_SCHEMA,
    register_agent, create_intent, evaluate_policy,
    issue_ticket, verify_action,
    print_header,
)

print_header("ATTACK: REPLAY ATTACK", "LLM06")

AGENT = "demo-replay-agent"
ACTION = "send_email"
RESOURCE = "cfo@company.com"
PAYLOAD = {"to": "cfo@company.com", "subject": "Q3 Report", "body": "See attached."}

register_agent(
    agent_id=AGENT,
    allowed_actions=[ACTION],
    allowed_resources=[RESOURCE],
    output_schemas={ACTION: EMAIL_SCHEMA},
)

intent = create_intent(AGENT, ACTION, RESOURCE, "Send Q3 report")
decision = evaluate_policy(intent["intent_id"], AGENT)
ticket = issue_ticket(decision["decision_id"], AGENT, PAYLOAD)
ticket_id = ticket["ticket_id"]

first = verify_action(ticket_id, AGENT, ACTION, RESOURCE, PAYLOAD)
if first.get("allowed"):
    print(f"First attempt: ALLOWED ✓")
else:
    print(f"First attempt: BLOCKED ✗ ({first.get('reason')})")

second = verify_action(ticket_id, AGENT, ACTION, RESOURCE, PAYLOAD)
if not second.get("allowed"):
    print(f"Second attempt (replay): BLOCKED ✗")
    print(f"Reason: {second.get('reason')}")
else:
    print(f"Second attempt: ALLOWED ✓ (unexpected — replay not blocked)")

print("This attack is stopped at: Check 5 — JTI Replay Prevention")
