import sys
import time
sys.path.insert(0, "/app")

from demo_helper import (
    EMAIL_SCHEMA,
    register_agent, create_intent, evaluate_policy,
    issue_ticket, verify_action,
    print_header,
)

print_header("ATTACK: RATE LIMIT", "LLM10")

AGENT = f"ratelimit-agent-{int(time.time())}"
ACTION = "send_email"
RESOURCE = "cfo@company.com"
LIMIT = 5
ATTEMPTS = 6

register_agent(
    agent_id=AGENT,
    allowed_actions=[ACTION],
    allowed_resources=[RESOURCE],
    output_schemas={ACTION: EMAIL_SCHEMA},
    max_actions_per_hour=LIMIT,
)

allowed_count = 0
blocked_count = 0

for i in range(1, ATTEMPTS + 1):
    payload = {"to": "cfo@company.com", "subject": f"Report #{i}", "body": f"Attempt {i}"}

    intent = create_intent(AGENT, ACTION, RESOURCE, f"Automated report #{i}")
    intent_id = intent.get("intent_id")

    decision = evaluate_policy(intent_id, AGENT)

    if not decision.get("allowed"):
        print(f"Request {i}: BLOCKED ✗")
        print(f"Reason: {decision.get('reason')}")
        print(f"Count: {decision.get('current_hourly_count')} | Limit: {LIMIT}")
        blocked_count += 1
        continue

    ticket = issue_ticket(decision["decision_id"], AGENT, payload)
    ticket_id = ticket["ticket_id"]

    result = verify_action(ticket_id, AGENT, ACTION, RESOURCE, payload)

    if result.get("allowed"):
        print(f"Request {i}: ALLOWED ✓")
        allowed_count += 1
    else:
        print(f"Request {i}: BLOCKED ✗")
        print(f"Reason: {result.get('reason')}")
        blocked_count += 1

print(f"This attack is stopped at: Policy — Rate Limiting")
