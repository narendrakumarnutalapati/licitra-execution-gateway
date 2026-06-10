from dataclasses import dataclass, field
from typing import Optional

import jsonschema
import jsonschema.exceptions

from packages.tickets.tickets import (
    verify_ticket_signature,
    reject_expired_ticket,
    reject_replayed_jti,
    calculate_payload_hash,
)
from packages.intent.intent import scan_for_injection


@dataclass
class SchemaResult:
    valid: bool
    violations: list


@dataclass
class VerificationResult:
    allowed: bool
    reason: str
    checks_passed: dict
    diff: Optional[dict]
    schema_violations: Optional[list]
    injection_findings: Optional[list]
    evidence_id: Optional[str]


def validate_output_schema(action: str, payload_dict: dict, agent: dict) -> SchemaResult:
    schema = agent.get("output_schemas", {}).get(action)
    if schema is None:
        return SchemaResult(valid=True, violations=[])

    violations = []
    try:
        jsonschema.validate(payload_dict, schema)
    except jsonschema.exceptions.ValidationError as e:
        violations.append(str(e.message))
    except jsonschema.ValidationError as e:
        violations.append(str(e.message))
    except Exception as e:
        violations.append(str(e))

    if violations:
        return SchemaResult(valid=False, violations=violations)
    return SchemaResult(valid=True, violations=[])


def verification_diff(check_name: str, expected, actual, mismatch_type: str) -> dict:
    return {
        "field": check_name,
        "expected_value": str(expected),
        "actual_value": str(actual),
        "mismatch_type": mismatch_type,
    }


def _resource_matches(resource: str, allowed_resources: list) -> bool:
    if not allowed_resources:
        return False
    for item in allowed_resources:
        if item.endswith("*"):
            if resource.startswith(item[:-1]):
                return True
        elif resource == item:
            return True
    return False


def verify_action(
    ticket: dict,
    agent: dict,
    action: str,
    resource: str,
    payload_dict: dict,
    used_jtis: set,
    system_public_key: Optional[str] = None,
) -> VerificationResult:
    checks_passed = {}
    diff = None
    schema_violations = None
    injection_findings = None

    # Check 1 — agent_registered
    passed = agent is not None and agent.get("is_active") is True
    checks_passed["agent_registered"] = passed
    if not passed:
        return VerificationResult(
            allowed=False, reason="AGENT_NOT_REGISTERED",
            checks_passed=checks_passed, diff=diff,
            schema_violations=schema_violations,
            injection_findings=injection_findings, evidence_id=None,
        )

    # Check 2 — ticket_exists
    passed = ticket is not None
    checks_passed["ticket_exists"] = passed
    if not passed:
        return VerificationResult(
            allowed=False, reason="TICKET_NOT_FOUND",
            checks_passed=checks_passed, diff=diff,
            schema_violations=schema_violations,
            injection_findings=injection_findings, evidence_id=None,
        )

    # Check 3 — signature_valid
    verify_key = system_public_key if system_public_key else agent["public_key"]
    passed = verify_ticket_signature(ticket, verify_key)
    checks_passed["signature_valid"] = passed
    if not passed:
        return VerificationResult(
            allowed=False, reason="INVALID_SIGNATURE",
            checks_passed=checks_passed, diff=diff,
            schema_violations=schema_violations,
            injection_findings=injection_findings, evidence_id=None,
        )

    # Check 4 — not_expired
    expired = reject_expired_ticket(ticket)
    checks_passed["not_expired"] = not expired
    if expired:
        return VerificationResult(
            allowed=False, reason="TICKET_EXPIRED",
            checks_passed=checks_passed, diff=diff,
            schema_violations=schema_violations,
            injection_findings=injection_findings, evidence_id=None,
        )

    # Check 5 — jti_not_replayed
    replayed = reject_replayed_jti(ticket["jti"], used_jtis)
    checks_passed["jti_not_replayed"] = not replayed
    if replayed:
        return VerificationResult(
            allowed=False, reason="JTI_REPLAYED",
            checks_passed=checks_passed, diff=diff,
            schema_violations=schema_violations,
            injection_findings=injection_findings, evidence_id=None,
        )
    used_jtis.add(ticket["jti"])

    # Check 6 — action_matches
    passed = action == ticket["action"]
    checks_passed["action_matches"] = passed
    if not passed:
        diff = verification_diff("action", ticket["action"], action, "action_mismatch")
        return VerificationResult(
            allowed=False, reason="ACTION_MISMATCH",
            checks_passed=checks_passed, diff=diff,
            schema_violations=schema_violations,
            injection_findings=injection_findings, evidence_id=None,
        )

    # Check 7 — resource_matches
    passed = resource == ticket["resource"]
    checks_passed["resource_matches"] = passed
    if not passed:
        diff = verification_diff("resource", ticket["resource"], resource, "resource_mismatch")
        return VerificationResult(
            allowed=False, reason="RESOURCE_MISMATCH",
            checks_passed=checks_passed, diff=diff,
            schema_violations=schema_violations,
            injection_findings=injection_findings, evidence_id=None,
        )

    # Check 8 — payload_hash_matches
    submitted_hash = calculate_payload_hash(payload_dict)
    passed = submitted_hash == ticket["payload_hash"]
    checks_passed["payload_hash_matches"] = passed
    if not passed:
        diff = verification_diff("payload_hash", ticket["payload_hash"], submitted_hash, "payload_tampered")
        return VerificationResult(
            allowed=False, reason="PAYLOAD_TAMPERED",
            checks_passed=checks_passed, diff=diff,
            schema_violations=schema_violations,
            injection_findings=injection_findings, evidence_id=None,
        )

    # Check 9 — output_schema_valid
    schema_result = validate_output_schema(action, payload_dict, agent)
    checks_passed["output_schema_valid"] = schema_result.valid
    if not schema_result.valid:
        schema_violations = schema_result.violations
        return VerificationResult(
            allowed=False, reason="OUTPUT_SCHEMA_VIOLATION",
            checks_passed=checks_passed, diff=diff,
            schema_violations=schema_violations,
            injection_findings=injection_findings, evidence_id=None,
        )

    # Check 10 — injection_rescan
    rescan_dict = {"action": action, "resource": resource, "purpose": str(payload_dict)}
    rescan_result = scan_for_injection(rescan_dict)
    checks_passed["injection_rescan"] = rescan_result.passed
    if not rescan_result.passed:
        injection_findings = rescan_result.patterns_found
        return VerificationResult(
            allowed=False, reason="INJECTION_DETECTED_AT_VERIFY",
            checks_passed=checks_passed, diff=diff,
            schema_violations=schema_violations,
            injection_findings=injection_findings, evidence_id=None,
        )

    # Check 11 — agent_scope
    action_allowed = action in agent.get("allowed_actions", [])
    resource_allowed = _resource_matches(resource, agent.get("allowed_resources", []))
    passed = action_allowed and resource_allowed
    checks_passed["agent_scope"] = passed
    if not passed:
        return VerificationResult(
            allowed=False, reason="OUT_OF_SCOPE",
            checks_passed=checks_passed, diff=diff,
            schema_violations=schema_violations,
            injection_findings=injection_findings, evidence_id=None,
        )

    # Check 12 — decision_binding
    decision_id = ticket.get("decision_id")
    passed = bool(decision_id)
    checks_passed["decision_binding"] = passed
    if not passed:
        return VerificationResult(
            allowed=False, reason="INVALID_DECISION_BINDING",
            checks_passed=checks_passed, diff=diff,
            schema_violations=schema_violations,
            injection_findings=injection_findings, evidence_id=None,
        )

    # All 12 passed
    checks_passed = {k: True for k in [
        "agent_registered", "ticket_exists", "signature_valid", "not_expired",
        "jti_not_replayed", "action_matches", "resource_matches",
        "payload_hash_matches", "output_schema_valid", "injection_rescan",
        "agent_scope", "decision_binding",
    ]}
    return VerificationResult(
        allowed=True, reason="All 12 checks passed",
        checks_passed=checks_passed, diff=None,
        schema_violations=None, injection_findings=None, evidence_id=None,
    )
