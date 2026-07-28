from datetime import datetime, timezone

from packages.mmr.mmr import (
    mmr_append,
    mmr_detect_tampering,
    mmr_proof,
    mmr_root,
    _compute_proof_from_db,
)


def append_audit_event(verification_record: dict, db=None) -> dict:
    allowed = verification_record.get("allowed", False)

    event_data = {
        "event_type": "VERIFY_ALLOWED" if allowed else "VERIFY_BLOCKED",
        "agent_id": verification_record.get("agent_id"),
        "action": verification_record.get("action"),
        "resource": verification_record.get("resource"),
        "decision": "ALLOWED" if allowed else "BLOCKED",
        "reason": verification_record.get("reason"),
        "payload_hash": verification_record.get("payload_hash"),
        "ticket_id": verification_record.get("ticket_id"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    return mmr_append(event_data, db=db)


def verify_audit_integrity(db=None) -> dict:
    return mmr_detect_tampering(db=db)


def get_inclusion_proof(leaf_index: int, db=None) -> dict:
    if db is not None:
        try:
            from apps.api.models import MmrLeaf
        except ImportError:
            from models import MmrLeaf  # type: ignore
        leaf_row = db.query(MmrLeaf).filter(MmrLeaf.leaf_index == leaf_index).first()
        if not leaf_row:
            raise IndexError(f"leaf_index {leaf_index} out of range")
        leaf_hash = leaf_row.leaf_hash
        proof = _compute_proof_from_db(leaf_index, db)
        root = mmr_root(db=db)
    else:
        proof = mmr_proof(leaf_index)
        from packages.mmr.mmr import mmr_leaves
        leaf_hash = mmr_leaves[leaf_index]["leaf_hash"]
        root = mmr_root()

    return {
        "leaf_hash": leaf_hash,
        "proof": proof,
        "root": root,
        "leaf_index": leaf_index,
    }


def get_current_root(db=None) -> str:
    return mmr_root(db=db)
