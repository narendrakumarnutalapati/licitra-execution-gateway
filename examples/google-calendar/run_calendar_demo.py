import sys
sys.path.insert(0, "/app")
sys.path.insert(0, "/app/apps/demo-agent")

from demo_helper import (
    register_agent, create_intent, evaluate_policy,
    issue_ticket, verify_action,
    print_header, print_allowed, print_blocked,
)

print_header("GOOGLE CALENDAR USE CASE")

AGENT = "demo-calendar-agent"
CREATE_ACTION = "create_meeting"
READ_ACTION = "read_meeting"
RESOURCE = "calendar/narendra"

MEETING_SCHEMA = {
    "type": "object",
    "required": ["attendees", "date", "title"],
    "properties": {
        "attendees": {"type": "array", "items": {"type": "string"}},
        "date": {"type": "string"},
        "title": {"type": "string"},
    },
    "additionalProperties": False,
}

register_agent(
    agent_id=AGENT,
    allowed_actions=[CREATE_ACTION, READ_ACTION],
    allowed_resources=[RESOURCE],
    output_schemas={CREATE_ACTION: MEETING_SCHEMA},
    action_cost_weights={CREATE_ACTION: 1.0, READ_ACTION: 0.5},
)

print("\n--- Scenario 1: Authorized meeting creation ---")
payload_1 = {"attendees": ["cfo@company.com", "cto@company.com"], "date": "2026-07-15", "title": "Q3 Review"}
intent = create_intent(AGENT, CREATE_ACTION, RESOURCE, "Schedule Q3 review meeting")
decision = evaluate_policy(intent["intent_id"], AGENT)
ticket = issue_ticket(decision["decision_id"], AGENT, payload_1)
result = verify_action(ticket["ticket_id"], AGENT, CREATE_ACTION, RESOURCE, payload_1)
if result.get("allowed"):
    print_allowed(result["evidence_id"], result["mmr_leaf_index"], result["mmr_root"])
else:
    print(f"UNEXPECTED BLOCK: {result.get('reason')}")

print("\n--- Scenario 2: Tampered attendee (change after approval) ---")
tampered_payload = {"attendees": ["attacker@evil.com"], "date": "2026-07-15", "title": "Q3 Review"}
intent_t = create_intent(AGENT, CREATE_ACTION, RESOURCE, "Schedule meeting — to be tampered")
decision_t = evaluate_policy(intent_t["intent_id"], AGENT)
ticket_t = issue_ticket(decision_t["decision_id"], AGENT, payload_1)
result = verify_action(ticket_t["ticket_id"], AGENT, CREATE_ACTION, RESOURCE, tampered_payload)
if not result.get("allowed"):
    print_blocked(reason=result.get("reason", "UNKNOWN"), diff=result.get("diff"), mmr_leaf=result.get("mmr_leaf_index"))
else:
    print("UNEXPECTED ALLOW")

print("\n--- Scenario 3: Replay the approved ticket ---")
intent2 = create_intent(AGENT, CREATE_ACTION, RESOURCE, "Another meeting")
decision2 = evaluate_policy(intent2["intent_id"], AGENT)
ticket2 = issue_ticket(decision2["decision_id"], AGENT, payload_1)
verify_action(ticket2["ticket_id"], AGENT, CREATE_ACTION, RESOURCE, payload_1)
replay = verify_action(ticket2["ticket_id"], AGENT, CREATE_ACTION, RESOURCE, payload_1)
if not replay.get("allowed"):
    print_blocked(reason=replay.get("reason", "UNKNOWN"), mmr_leaf=replay.get("mmr_leaf_index"))
else:
    print("UNEXPECTED ALLOW (replay not blocked)")
