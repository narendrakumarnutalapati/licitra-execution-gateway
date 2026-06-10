import sys
sys.path.insert(0, "/app")

from demo_helper import (
    verify_action,
    print_header, print_blocked,
)

print_header("ATTACK: FAKE AGENT", "LLM06")

result = verify_action(
    ticket_id="fake-ticket-99999",
    agent_id="fake-agent-99999",
    action="send_email",
    resource="cfo@company.com",
    payload={"to": "cfo@company.com", "subject": "test", "body": "test"},
)

print_blocked(
    reason=result.get("reason", "UNKNOWN"),
    mmr_leaf=result.get("mmr_leaf_index"),
)
print("This attack is stopped at: Check 1 — Agent Registration")
