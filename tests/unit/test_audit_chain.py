import pytest

from packages.audit_chain import (
    append_audit_event,
    verify_audit_integrity,
    get_inclusion_proof,
    get_current_root,
)
from packages.mmr.mmr import (
    reset_mmr_for_testing,
    mmr_size,
    mmr_leaves,
    mmr_verify_proof,
)


def _record(allowed=True):
    return {
        "allowed": allowed,
        "agent_id": "agent-test",
        "action": "send_email",
        "resource": "cfo@company.com",
        "reason": "All policy checks passed" if allowed else "ACTION_NOT_ALLOWED",
        "payload_hash": "a" * 64,
        "ticket_id": "ticket-001",
    }


def test_event_appended_to_mmr():
    reset_mmr_for_testing()
    result = append_audit_event(_record(allowed=True))
    assert mmr_size() == 1
    assert "leaf_index" in result
    assert "leaf_hash" in result
    assert "root_hash" in result
    assert "proof" in result


def test_inclusion_proof_valid_after_append():
    reset_mmr_for_testing()
    append_audit_event(_record(allowed=True))
    inclusion = get_inclusion_proof(0)
    assert mmr_verify_proof(
        inclusion["leaf_hash"],
        inclusion["proof"],
        inclusion["root"],
        0,
    ) is True


def test_integrity_passes_on_clean_chain():
    reset_mmr_for_testing()
    for i in range(3):
        append_audit_event(_record(allowed=(i % 2 == 0)))
    result = verify_audit_integrity()
    assert result["intact"] is True
    assert result["tampered_leaf_index"] is None


def test_tampering_detected():
    reset_mmr_for_testing()
    for _ in range(3):
        append_audit_event(_record(allowed=True))
    mmr_leaves[1]["event_data"] = {"tampered": True}
    result = verify_audit_integrity()
    assert result["intact"] is False
    assert result["tampered_leaf_index"] == 1


def test_get_current_root_returns_hash():
    reset_mmr_for_testing()
    append_audit_event(_record(allowed=True))
    root = get_current_root()
    assert len(root) == 64
    assert all(c in "0123456789abcdef" for c in root)
    assert root != "0" * 64
