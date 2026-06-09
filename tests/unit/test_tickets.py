import pytest
from datetime import datetime, timezone, timedelta

from packages.tickets import (
    generate_keypair,
    calculate_payload_hash,
    issue_execution_ticket,
    verify_ticket_signature,
    reject_expired_ticket,
    reject_replayed_jti,
)


SAMPLE_PAYLOAD = {"tool": "send_email", "to": "user@example.com", "subject": "Hello"}
SAMPLE_CONSTRAINTS = {"max_recipients": 1, "allowed_domains": ["example.com"]}


def _issue(keypair, expires_at):
    return issue_execution_ticket(
        decision_id="dec-001",
        agent_id="agent-abc",
        action="send_email",
        resource="gmail",
        purpose="notify user",
        constraints=SAMPLE_CONSTRAINTS,
        payload=SAMPLE_PAYLOAD,
        expires_at=expires_at,
        private_key_hex=keypair["private_key_hex"],
    )


def test_valid_ticket_accepted():
    keypair = generate_keypair()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    ticket = _issue(keypair, expires_at)
    assert verify_ticket_signature(ticket, keypair["public_key_hex"]) is True


def test_expired_ticket_rejected():
    keypair = generate_keypair()
    expires_at = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    ticket = _issue(keypair, expires_at)
    assert reject_expired_ticket(ticket) is True


def test_valid_ticket_not_expired():
    keypair = generate_keypair()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    ticket = _issue(keypair, expires_at)
    assert reject_expired_ticket(ticket) is False


def test_replayed_jti_rejected():
    keypair = generate_keypair()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    ticket = _issue(keypair, expires_at)
    used_jtis = {ticket["jti"]}
    assert reject_replayed_jti(ticket["jti"], used_jtis) is True


def test_new_jti_not_rejected():
    used_jtis = set()
    assert reject_replayed_jti("brand-new-jti-xyz", used_jtis) is False


def test_payload_hash_deterministic():
    result1 = calculate_payload_hash(SAMPLE_PAYLOAD)
    result2 = calculate_payload_hash(SAMPLE_PAYLOAD)
    assert result1 == result2
    assert len(result1) == 64
    assert all(c in "0123456789abcdef" for c in result1)


def test_invalid_signature_returns_false():
    keypair_a = generate_keypair()
    keypair_b = generate_keypair()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    ticket = _issue(keypair_a, expires_at)
    result = verify_ticket_signature(ticket, keypair_b["public_key_hex"])
    assert result is False
