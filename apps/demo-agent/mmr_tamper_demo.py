import sys
sys.path.insert(0, "/app")

import httpx

from demo_helper import (
    EMAIL_SCHEMA, BASE,
    register_agent, create_intent, evaluate_policy,
    issue_ticket, verify_action,
    print_header, get_mmr_root,
)

print_header("ATTACK: MMR AUDIT CHAIN TAMPER")

AGENT = "demo-mmr-agent"
ACTION = "send_email"
RESOURCE = "cfo@company.com"

register_agent(
    agent_id=AGENT,
    allowed_actions=[ACTION],
    allowed_resources=[RESOURCE],
    output_schemas={ACTION: EMAIL_SCHEMA},
)

leaf_count = 0
for i in range(1, 6):
    payload = {"to": "cfo@company.com", "subject": f"Report #{i}", "body": f"Run {i}"}
    intent = create_intent(AGENT, ACTION, RESOURCE, f"Authorized run #{i}")
    decision = evaluate_policy(intent["intent_id"], AGENT)
    ticket = issue_ticket(decision["decision_id"], AGENT, payload)
    result = verify_action(ticket["ticket_id"], AGENT, ACTION, RESOURCE, payload)
    if result.get("allowed"):
        leaf_count = result["mmr_leaf_index"] + 1

mmr_before = get_mmr_root()
initial_root = mmr_before.get("mmr_root", "unknown")
print(f"Initial MMR root: {initial_root[:20]}...")
print(f"Leaves appended: {leaf_count}")

tamper_leaf = 2
tamper_resp = httpx.post(f"{BASE}/debug/tamper-mmr", json={
    "leaf_index": tamper_leaf,
    "new_data": {"tampered": True, "agent_id": "CORRUPTED"},
})

if tamper_resp.status_code == 404:
    print("ERROR: /debug/tamper-mmr endpoint not available.")
    print("Start the API with DEBUG=true to enable this endpoint.")
    sys.exit(1)

print(f"Tampered leaf_index: {tamper_leaf} directly in PostgreSQL")

mmr_after = get_mmr_root()
integrity = mmr_after.get("integrity", "UNKNOWN")

if integrity == "TAMPERED":
    print(f"MMR INTEGRITY VIOLATION DETECTED ✗")
    print(f"integrity: TAMPERED")
    print(f"Tampered at leaf: {tamper_leaf}")
    print("This proves: Even database-level tampering is detected")
else:
    print(f"integrity: {integrity}")
    print("WARNING: Tampering was NOT detected (unexpected)")
