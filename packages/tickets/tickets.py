import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

import nacl.signing
import nacl.encoding
import nacl.exceptions


def generate_keypair() -> dict:
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    return {
        "private_key_hex": signing_key.encode(nacl.encoding.HexEncoder).decode(),
        "public_key_hex": verify_key.encode(nacl.encoding.HexEncoder).decode(),
    }


def calculate_payload_hash(payload_dict: dict) -> str:
    canonical = json.dumps(payload_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def issue_execution_ticket(
    decision_id: str,
    agent_id: str,
    action: str,
    resource: str,
    purpose: str,
    constraints: dict,
    payload: dict,
    expires_at: str,
    private_key_hex: str,
) -> dict:
    constraints_hash = hashlib.sha256(
        json.dumps(constraints, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    payload_hash = calculate_payload_hash(payload)

    output_schema_hash = hashlib.sha256(b"").hexdigest()

    jti = str(uuid4())
    ticket_id = str(uuid4())
    issued_at = datetime.now(timezone.utc).isoformat()

    canonical_ticket = {
        "action": action,
        "agent_id": agent_id,
        "constraints_hash": constraints_hash,
        "decision_id": decision_id,
        "expires_at": expires_at,
        "issued_at": issued_at,
        "jti": jti,
        "output_schema_hash": output_schema_hash,
        "payload_hash": payload_hash,
        "purpose": purpose,
        "resource": resource,
        "status": "ACTIVE",
        "ticket_id": ticket_id,
    }

    canonical_json = json.dumps(canonical_ticket, sort_keys=True, separators=(",", ":")).encode()

    signing_key = nacl.signing.SigningKey(
        private_key_hex.encode(), encoder=nacl.encoding.HexEncoder
    )
    signed = signing_key.sign(canonical_json)
    signature_hex = signed.signature.hex()

    return {**canonical_ticket, "issuer_signature": signature_hex}


def verify_ticket_signature(ticket_dict: dict, public_key_hex: str) -> bool:
    try:
        canonical_ticket = {k: v for k, v in ticket_dict.items() if k != "issuer_signature"}
        canonical_json = json.dumps(canonical_ticket, sort_keys=True, separators=(",", ":")).encode()

        signature_bytes = bytes.fromhex(ticket_dict["issuer_signature"])

        verify_key = nacl.signing.VerifyKey(
            public_key_hex.encode(), encoder=nacl.encoding.HexEncoder
        )
        verify_key.verify(canonical_json, signature_bytes)
        return True
    except Exception:
        return False


def reject_expired_ticket(ticket_dict: dict) -> bool:
    expires_at = datetime.fromisoformat(ticket_dict["expires_at"])
    now = datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at <= now


def reject_replayed_jti(jti: str, used_jtis: set) -> bool:
    return jti in used_jtis
