import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from .patterns import INJECTION_PATTERNS


@dataclass
class ScanResult:
    passed: bool
    patterns_found: list
    risk_score: float


def scan_for_injection(intent_dict: dict) -> ScanResult:
    fields_to_scan = []

    for key in ("action", "resource", "purpose"):
        value = intent_dict.get(key)
        if isinstance(value, str):
            fields_to_scan.append(value)

    constraints = intent_dict.get("constraints")
    if isinstance(constraints, dict):
        for v in constraints.values():
            if isinstance(v, str):
                fields_to_scan.append(v)

    risk_score = 0.0
    medium_matches = []

    for value in fields_to_scan:
        for pat in INJECTION_PATTERNS:
            if re.search(pat["pattern"], value, re.IGNORECASE):
                if pat["severity"] == "HIGH":
                    return ScanResult(passed=False, patterns_found=[pat["id"]], risk_score=1.0)
                elif pat["severity"] == "MEDIUM":
                    if pat["id"] not in medium_matches:
                        medium_matches.append(pat["id"])
                        risk_score += pat["risk_score_add"]

    if risk_score >= 0.7:
        return ScanResult(passed=False, patterns_found=medium_matches, risk_score=risk_score)

    return ScanResult(passed=True, patterns_found=[], risk_score=0.0)


def canonicalize_intent(intent_dict: dict) -> str:
    return json.dumps(intent_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_intent(intent_dict: dict) -> str:
    return hashlib.sha256(canonicalize_intent(intent_dict).encode("utf-8")).hexdigest()


def create_intent(
    user_id: str,
    agent_id: str,
    action: str,
    resource: str,
    purpose: str,
    constraints: dict,
    expires_at: str,
) -> dict:
    probe = {
        "action": action,
        "resource": resource,
        "purpose": purpose,
        "constraints": constraints,
    }
    scan = scan_for_injection(probe)
    if not scan.passed:
        raise ValueError(f"INJECTION_DETECTED: patterns_found={scan.patterns_found}")

    return {
        "intent_id": str(uuid4()),
        "user_id": user_id,
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "purpose": purpose,
        "constraints": constraints,
        "expires_at": expires_at,
        "injection_scan_result": "PASS",
        "injection_patterns_found": None,
        "status": "PENDING",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
