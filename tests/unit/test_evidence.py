import pytest

from packages.evidence import generate_evidence_json, generate_evidence_pdf

REQUIRED_FIELDS = [
    "evidence_id", "intent_id", "decision_id", "ticket_id", "agent_id",
    "action", "resource", "decision", "reason", "diff", "schema_violations",
    "injection_findings", "payload_hash", "ticket_hash",
    "mmr_leaf_index", "mmr_leaf_hash", "mmr_root", "mmr_proof",
    "mmr_proof_size", "created_at",
]


def _vr(**overrides):
    base = {
        "intent_id": "intent-001",
        "decision_id": "dec-001",
        "ticket_id": "ticket-001",
        "agent_id": "agent-001",
        "action": "send_email",
        "resource": "cfo@company.com",
        "allowed": True,
        "reason": "All policy checks passed",
        "payload_hash": "a" * 64,
        "ticket_hash": "b" * 64,
    }
    base.update(overrides)
    return base


def _mmr():
    return {
        "leaf_index": 0,
        "leaf_hash": "c" * 64,
        "root_hash": "d" * 64,
        "proof": {"siblings": ["e" * 64], "peaks": [None], "peak_index": 0},
    }


def test_evidence_json_has_all_required_fields():
    evidence = generate_evidence_json(_vr(), _mmr())
    for field in REQUIRED_FIELDS:
        assert field in evidence, f"Missing field: {field}"


def test_diff_present_when_blocked():
    diff = {
        "field": "to",
        "expected_value": "cfo@company.com",
        "actual_value": "attacker@evil.com",
        "mismatch_type": "payload_tampered",
    }
    vr = _vr(allowed=False, reason="PAYLOAD_MISMATCH", diff=diff)
    evidence = generate_evidence_json(vr, _mmr())
    assert evidence["diff"] is not None
    assert evidence["decision"] == "BLOCKED"


def test_allowed_decision_correct():
    vr = _vr(allowed=True)
    evidence = generate_evidence_json(vr, _mmr())
    assert evidence["decision"] == "ALLOWED"


def test_pdf_generates_without_error():
    evidence = generate_evidence_json(_vr(), _mmr())
    pdf = generate_evidence_pdf(evidence)
    assert isinstance(pdf, bytes)
    assert len(pdf) > 1000


def test_pdf_blocked_with_diff():
    diff = {
        "field": "to",
        "expected_value": "cfo@company.com",
        "actual_value": "attacker@evil.com",
        "mismatch_type": "payload_tampered",
    }
    vr = _vr(allowed=False, reason="PAYLOAD_MISMATCH", diff=diff)
    evidence = generate_evidence_json(vr, _mmr())
    evidence["decision"] = "BLOCKED"
    pdf = generate_evidence_pdf(evidence)
    assert isinstance(pdf, bytes)
    assert len(pdf) > 1000
