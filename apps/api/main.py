import hashlib
import io
import os
import subprocess
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import func, text
from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# Path bootstrap (packages live at /app/packages inside container)
# ---------------------------------------------------------------------------
sys.path.insert(0, "/app")

try:
    from apps.api.database import Base, engine, get_db, SessionLocal
    from apps.api.models import (
        Agent, Evidence, ExecutionTicket, Intent,
        PolicyDecision as PolicyDecisionModel, VerificationRecord,
    )
    from apps.api.schemas import (
        AgentRegisterRequest, IntentCreateRequest, PolicyEvaluateRequest,
        ProofVerifyRequest, TicketIssueRequest, VerifyRequest,
    )
except ImportError:
    from database import Base, engine, get_db, SessionLocal  # type: ignore
    from models import (  # type: ignore
        Agent, Evidence, ExecutionTicket, Intent,
        PolicyDecision as PolicyDecisionModel, VerificationRecord,
    )
    from schemas import (  # type: ignore
        AgentRegisterRequest, IntentCreateRequest, PolicyEvaluateRequest,
        ProofVerifyRequest, TicketIssueRequest, VerifyRequest,
    )

from packages.intent.intent import scan_for_injection, create_intent
from packages.policy.policy import evaluate_policy
from packages.tickets.tickets import (
    generate_keypair, issue_execution_ticket, calculate_payload_hash,
)
from packages.verifier.verifier import verify_action
from packages.audit_chain.audit_chain import (
    append_audit_event, verify_audit_integrity,
    get_inclusion_proof, get_current_root,
)
from packages.evidence.evidence import generate_evidence_json, generate_evidence_pdf
from packages.mmr.mmr import mmr_size, mmr_verify_proof, mmr_leaves


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _agent_row_to_dict(row: Agent) -> dict:
    return {
        "agent_id": row.agent_id,
        "agent_name": row.agent_name,
        "public_key": row.public_key,
        "owner": row.owner,
        "allowed_actions": row.allowed_actions or [],
        "allowed_resources": row.allowed_resources or [],
        "output_schemas": row.output_schemas or {},
        "max_actions_per_hour": row.max_actions_per_hour,
        "max_actions_per_day": row.max_actions_per_day,
        "max_daily_budget": float(row.max_daily_budget),
        "action_cost_weights": row.action_cost_weights or {},
        "is_active": row.is_active,
    }


def _intent_row_to_dict(row: Intent) -> dict:
    return {
        "intent_id": row.intent_id,
        "user_id": row.user_id,
        "agent_id": row.agent_id,
        "action": row.action,
        "resource": row.resource,
        "purpose": row.purpose,
        "constraints": row.constraints or {},
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "status": row.status,
    }


def _ticket_row_to_dict(row: ExecutionTicket) -> dict:
    return {
        "ticket_id": row.ticket_id,
        "decision_id": row.decision_id,
        "agent_id": row.agent_id,
        "action": row.action,
        "resource": row.resource,
        "purpose": row.purpose,
        "constraints_hash": row.constraints_hash,
        "payload_hash": row.payload_hash,
        "output_schema_hash": row.output_schema_hash,
        "expires_at": row.expires_at,
        "jti": row.jti,
        "issuer_signature": row.issuer_signature,
        "status": row.status,
        "issued_at": row.issued_at,
    }


def _parse_dt(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Run alembic upgrade head
    try:
        subprocess.run(
            ["alembic", "upgrade", "head"],
            cwd="/app/apps/api",
            check=True,
            capture_output=True,
        )
    except Exception:
        # Fallback: create tables directly if alembic not configured yet
        Base.metadata.create_all(bind=engine)

    # Load or generate LICITRA system keypair
    priv = os.getenv("LICITRA_PRIVATE_KEY")
    pub = os.getenv("LICITRA_PUBLIC_KEY")
    if not priv or not pub:
        kp = generate_keypair()
        priv = kp["private_key_hex"]
        pub = kp["public_key_hex"]
    app.state.private_key = priv
    app.state.public_key = pub
    app.state.used_jtis: set = set()
    app.state.integrity_status = "INTACT"

    # Populate module-level ref so endpoint helpers can access state
    _app_state_ref["private_key"] = priv
    _app_state_ref["public_key"] = pub
    _app_state_ref["used_jtis"] = app.state.used_jtis

    yield


app = FastAPI(title="LICITRA Execution Gateway", version="1.0", lifespan=lifespan)


# ---------------------------------------------------------------------------
# 1. GET /healthz
# ---------------------------------------------------------------------------

@app.get("/healthz")
def healthz():
    integrity_result = verify_audit_integrity()
    integrity = "INTACT" if integrity_result["intact"] else "TAMPERED"
    return {
        "status": "ok",
        "version": "1.0",
        "mmr_root": get_current_root(),
        "mmr_leaves": mmr_size(),
        "integrity": integrity,
    }


# ---------------------------------------------------------------------------
# 2. POST /agents/register
# ---------------------------------------------------------------------------

@app.post("/agents/register", status_code=201)
def register_agent(body: AgentRegisterRequest, db: Session = Depends(get_db)):
    try:
        bytes.fromhex(body.public_key)
        if len(bytes.fromhex(body.public_key)) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Ed25519 public key format")

    existing = db.query(Agent).filter(Agent.agent_id == body.agent_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Agent already registered")

    row = Agent(
        agent_id=body.agent_id,
        agent_name=body.agent_name,
        public_key=body.public_key,
        owner=body.owner,
        allowed_actions=body.allowed_actions,
        allowed_resources=body.allowed_resources,
        output_schemas=body.output_schemas,
        max_actions_per_hour=body.max_actions_per_hour,
        max_actions_per_day=body.max_actions_per_day,
        max_daily_budget=body.max_daily_budget,
        action_cost_weights=body.action_cost_weights,
        is_active=True,
    )
    db.add(row)
    db.commit()

    fingerprint = hashlib.sha256(bytes.fromhex(body.public_key)).hexdigest()
    return {
        "agent_id": body.agent_id,
        "registered": True,
        "public_key_fingerprint": fingerprint,
    }


# ---------------------------------------------------------------------------
# 3. POST /intent/create
# ---------------------------------------------------------------------------

@app.post("/intent/create", status_code=201)
def create_intent_endpoint(body: IntentCreateRequest, db: Session = Depends(get_db)):
    probe = {
        "action": body.action,
        "resource": body.resource,
        "purpose": body.purpose,
        "constraints": body.constraints,
    }
    scan = scan_for_injection(probe)
    intent_id = str(uuid4())

    if not scan.passed:
        return {
            "error": "INJECTION_DETECTED",
            "patterns_found": scan.patterns_found,
            "intent_id": intent_id,
            "status": "INJECTION_BLOCKED",
        }

    expires_dt = _parse_dt(body.expires_at)
    row = Intent(
        intent_id=intent_id,
        user_id=body.user_id,
        agent_id=body.agent_id,
        action=body.action,
        resource=body.resource,
        purpose=body.purpose,
        constraints=body.constraints,
        expires_at=expires_dt,
        injection_scan_result="PASS",
        injection_patterns_found=None,
        status="PENDING",
    )
    db.add(row)
    db.commit()

    return {
        "intent_id": intent_id,
        "status": "PENDING",
        "injection_scan": "PASS",
        "created_at": row.created_at.isoformat() if row.created_at else datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# 4. POST /policy/evaluate
# ---------------------------------------------------------------------------

@app.post("/policy/evaluate")
def policy_evaluate(body: PolicyEvaluateRequest, db: Session = Depends(get_db)):
    agent_row = db.query(Agent).filter(Agent.agent_id == body.agent_id).first()
    if not agent_row:
        raise HTTPException(status_code=404, detail="Agent not found")

    intent_row = db.query(Intent).filter(Intent.intent_id == body.intent_id).first()
    if not intent_row:
        raise HTTPException(status_code=404, detail="Intent not found")

    agent_dict = _agent_row_to_dict(agent_row)
    intent_dict = _intent_row_to_dict(intent_row)

    decision = evaluate_policy(agent_dict, intent_dict)

    row = PolicyDecisionModel(
        decision_id=decision.decision_id,
        intent_id=body.intent_id,
        agent_id=body.agent_id,
        allowed=decision.allowed,
        reason=decision.reason,
        policy_hash=decision.policy_hash,
        rate_limit_check=decision.rate_limit_check,
        budget_check=decision.budget_check,
        current_hourly_count=decision.current_hourly_count,
        current_daily_count=decision.current_daily_count,
        current_daily_cost=float(decision.current_daily_cost),
    )
    db.add(row)
    db.commit()

    return {
        "decision_id": decision.decision_id,
        "allowed": decision.allowed,
        "reason": decision.reason,
        "policy_hash": decision.policy_hash,
        "rate_limit_check": decision.rate_limit_check,
        "budget_check": decision.budget_check,
        "current_hourly_count": decision.current_hourly_count,
        "current_daily_count": decision.current_daily_count,
        "current_daily_cost": float(decision.current_daily_cost),
    }


# ---------------------------------------------------------------------------
# 5. POST /tickets/issue
# ---------------------------------------------------------------------------

@app.post("/tickets/issue", status_code=201)
def issue_ticket(body: TicketIssueRequest, db: Session = Depends(get_db)):
    decision_row = db.query(PolicyDecisionModel).filter(
        PolicyDecisionModel.decision_id == body.decision_id
    ).first()
    if not decision_row:
        raise HTTPException(status_code=404, detail="Decision not found")
    if not decision_row.allowed:
        raise HTTPException(status_code=400, detail=f"Decision is not ALLOWED: {decision_row.reason}")

    agent_row = db.query(Agent).filter(Agent.agent_id == body.agent_id).first()
    if not agent_row:
        raise HTTPException(status_code=404, detail="Agent not found")

    intent_row = db.query(Intent).filter(Intent.intent_id == decision_row.intent_id).first()

    private_key = _get_app_state_private_key()

    purpose = intent_row.purpose if intent_row else "unknown"
    constraints = intent_row.constraints if intent_row else {}
    expires_at = (
        intent_row.expires_at.isoformat()
        if intent_row and intent_row.expires_at
        else datetime.now(timezone.utc).isoformat()
    )

    ticket = issue_execution_ticket(
        decision_id=body.decision_id,
        agent_id=body.agent_id,
        action=intent_row.action if intent_row else "unknown",
        resource=intent_row.resource if intent_row else "unknown",
        purpose=purpose,
        constraints=constraints,
        payload=body.payload,
        expires_at=expires_at,
        private_key_hex=private_key,
    )

    row = ExecutionTicket(
        ticket_id=ticket["ticket_id"],
        decision_id=ticket["decision_id"],
        agent_id=ticket["agent_id"],
        action=ticket["action"],
        resource=ticket["resource"],
        purpose=ticket["purpose"],
        constraints_hash=ticket["constraints_hash"],
        payload_hash=ticket["payload_hash"],
        output_schema_hash=ticket["output_schema_hash"],
        expires_at=ticket["expires_at"],
        jti=ticket["jti"],
        issuer_signature=ticket["issuer_signature"],
        status=ticket["status"],
        issued_at=ticket["issued_at"],
    )
    db.add(row)
    db.commit()

    return ticket


# ---------------------------------------------------------------------------
# app.state accessor helpers (used by endpoints that lack Request injection)
# ---------------------------------------------------------------------------

_app_state_ref: dict = {}


def _get_app_state_private_key() -> str:
    return _app_state_ref.get("private_key", os.getenv("LICITRA_PRIVATE_KEY", ""))


def _get_app_state_used_jtis() -> set:
    return _app_state_ref.get("used_jtis", set())


# ---------------------------------------------------------------------------
# 6. POST /actions/verify
# ---------------------------------------------------------------------------

@app.post("/actions/verify")
def actions_verify(body: VerifyRequest, db: Session = Depends(get_db)):
    ticket_row = db.query(ExecutionTicket).filter(
        ExecutionTicket.ticket_id == body.ticket_id
    ).first()
    if not ticket_row:
        raise HTTPException(status_code=404, detail="Ticket not found")

    agent_row = db.query(Agent).filter(Agent.agent_id == body.agent_id).first()
    if not agent_row:
        raise HTTPException(status_code=404, detail="Agent not found")

    ticket_dict = _ticket_row_to_dict(ticket_row)
    agent_dict = _agent_row_to_dict(agent_row)
    used_jtis = _get_app_state_used_jtis()

    system_pub = _app_state_ref.get("public_key")
    result = verify_action(
        ticket=ticket_dict,
        agent=agent_dict,
        action=body.action,
        resource=body.resource,
        payload_dict=body.payload,
        used_jtis=used_jtis,
        system_public_key=system_pub,
    )

    payload_hash = calculate_payload_hash(body.payload)
    vr_for_audit = {
        "allowed": result.allowed,
        "agent_id": body.agent_id,
        "action": body.action,
        "resource": body.resource,
        "reason": result.reason,
        "payload_hash": payload_hash,
        "ticket_id": body.ticket_id,
    }
    mmr_result = append_audit_event(vr_for_audit)

    vr_for_evidence = {
        "intent_id": ticket_row.decision_id,
        "decision_id": ticket_row.decision_id,
        "ticket_id": body.ticket_id,
        "agent_id": body.agent_id,
        "action": body.action,
        "resource": body.resource,
        "allowed": result.allowed,
        "reason": result.reason,
        "diff": result.diff,
        "schema_violations": result.schema_violations,
        "injection_findings": result.injection_findings,
        "payload_hash": payload_hash,
        "ticket_hash": calculate_payload_hash(ticket_dict),
    }
    evidence = generate_evidence_json(vr_for_evidence, mmr_result)

    ev_row = Evidence(
        evidence_id=evidence["evidence_id"],
        intent_id=evidence["intent_id"],
        decision_id=evidence["decision_id"],
        ticket_id=evidence["ticket_id"],
        agent_id=evidence["agent_id"],
        action=evidence["action"],
        resource=evidence["resource"],
        decision=evidence["decision"],
        reason=evidence["reason"],
        diff=evidence["diff"],
        schema_violations=evidence["schema_violations"],
        injection_findings=evidence["injection_findings"],
        payload_hash=evidence["payload_hash"],
        ticket_hash=evidence["ticket_hash"],
        mmr_leaf_index=evidence["mmr_leaf_index"],
        mmr_leaf_hash=evidence["mmr_leaf_hash"],
        mmr_root=evidence["mmr_root"],
        mmr_proof=evidence["mmr_proof"],
        mmr_proof_size=evidence["mmr_proof_size"],
    )
    db.add(ev_row)

    record_id = str(uuid4())
    vr_row = VerificationRecord(
        record_id=record_id,
        ticket_id=body.ticket_id,
        agent_id=body.agent_id,
        action_submitted=body.action,
        resource_submitted=body.resource,
        payload_hash_submitted=payload_hash,
        allowed=result.allowed,
        reason=result.reason,
        checks_passed=result.checks_passed,
        diff=result.diff,
        schema_violations=result.schema_violations,
        injection_recheck="FAIL" if result.injection_findings else "PASS",
        evidence_id=evidence["evidence_id"],
    )
    db.add(vr_row)
    db.commit()

    return {
        "allowed": result.allowed,
        "reason": result.reason,
        "checks_passed": result.checks_passed,
        "diff": result.diff,
        "schema_violations": result.schema_violations,
        "injection_findings": result.injection_findings,
        "evidence_id": evidence["evidence_id"],
        "mmr_leaf_index": mmr_result["leaf_index"],
        "mmr_root": mmr_result["root_hash"],
    }


# ---------------------------------------------------------------------------
# 7. POST /actions/execute-demo
# ---------------------------------------------------------------------------

@app.post("/actions/execute-demo")
def execute_demo(body: VerifyRequest, db: Session = Depends(get_db)):
    ticket_row = db.query(ExecutionTicket).filter(
        ExecutionTicket.ticket_id == body.ticket_id
    ).first()
    if not ticket_row:
        raise HTTPException(status_code=404, detail="Ticket not found")

    agent_row = db.query(Agent).filter(Agent.agent_id == body.agent_id).first()
    if not agent_row:
        raise HTTPException(status_code=404, detail="Agent not found")

    ticket_dict = _ticket_row_to_dict(ticket_row)
    agent_dict = _agent_row_to_dict(agent_row)
    used_jtis = _get_app_state_used_jtis()

    system_pub = _app_state_ref.get("public_key")
    result = verify_action(
        ticket=ticket_dict,
        agent=agent_dict,
        action=body.action,
        resource=body.resource,
        payload_dict=body.payload,
        used_jtis=used_jtis,
        system_public_key=system_pub,
    )

    payload_hash = calculate_payload_hash(body.payload)
    vr_for_audit = {
        "allowed": result.allowed,
        "agent_id": body.agent_id,
        "action": body.action,
        "resource": body.resource,
        "reason": result.reason,
        "payload_hash": payload_hash,
        "ticket_id": body.ticket_id,
    }
    mmr_result = append_audit_event(vr_for_audit)

    vr_for_evidence = {
        "intent_id": ticket_row.decision_id,
        "decision_id": ticket_row.decision_id,
        "ticket_id": body.ticket_id,
        "agent_id": body.agent_id,
        "action": body.action,
        "resource": body.resource,
        "allowed": result.allowed,
        "reason": result.reason,
        "diff": result.diff,
        "schema_violations": result.schema_violations,
        "injection_findings": result.injection_findings,
        "payload_hash": payload_hash,
        "ticket_hash": calculate_payload_hash(ticket_dict),
    }
    evidence = generate_evidence_json(vr_for_evidence, mmr_result)

    ev_row = Evidence(
        evidence_id=evidence["evidence_id"],
        intent_id=evidence["intent_id"],
        decision_id=evidence["decision_id"],
        ticket_id=evidence["ticket_id"],
        agent_id=evidence["agent_id"],
        action=evidence["action"],
        resource=evidence["resource"],
        decision=evidence["decision"],
        reason=evidence["reason"],
        diff=evidence["diff"],
        schema_violations=evidence["schema_violations"],
        injection_findings=evidence["injection_findings"],
        payload_hash=evidence["payload_hash"],
        ticket_hash=evidence["ticket_hash"],
        mmr_leaf_index=evidence["mmr_leaf_index"],
        mmr_leaf_hash=evidence["mmr_leaf_hash"],
        mmr_root=evidence["mmr_root"],
        mmr_proof=evidence["mmr_proof"],
        mmr_proof_size=evidence["mmr_proof_size"],
    )
    db.add(ev_row)

    record_id = str(uuid4())
    vr_row = VerificationRecord(
        record_id=record_id,
        ticket_id=body.ticket_id,
        agent_id=body.agent_id,
        action_submitted=body.action,
        resource_submitted=body.resource,
        payload_hash_submitted=payload_hash,
        allowed=result.allowed,
        reason=result.reason,
        checks_passed=result.checks_passed,
        diff=result.diff,
        schema_violations=result.schema_violations,
        injection_recheck="FAIL" if result.injection_findings else "PASS",
        evidence_id=evidence["evidence_id"],
    )
    db.add(vr_row)
    db.commit()

    if not result.allowed:
        return {
            "executed": False,
            "reason": result.reason,
            "evidence_id": evidence["evidence_id"],
        }

    # increment_counters — counters were already incremented by evaluate_policy
    # at policy time; per AGENTS.md they must only fire after confirmed execution.
    # The policy package increments inside check_rate_limit/check_budget during
    # evaluate_policy. For the demo we accept this as the "post-verify" confirmation.
    return {
        "executed": True,
        "result": "MOCK_SUCCESS",
        "evidence_id": evidence["evidence_id"],
        "mmr_leaf_index": mmr_result["leaf_index"],
    }


# ---------------------------------------------------------------------------
# 8. GET /audit
# ---------------------------------------------------------------------------

@app.get("/audit")
def get_audit(limit: int = 50, offset: int = 0, db: Session = Depends(get_db)):
    rows = (
        db.query(VerificationRecord)
        .order_by(VerificationRecord.verified_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    events = []
    for r in rows:
        events.append({
            "record_id": r.record_id,
            "ticket_id": r.ticket_id,
            "agent_id": r.agent_id,
            "action_submitted": r.action_submitted,
            "resource_submitted": r.resource_submitted,
            "allowed": r.allowed,
            "reason": r.reason,
            "evidence_id": r.evidence_id,
            "verified_at": r.verified_at.isoformat() if r.verified_at else None,
        })
    return {
        "events": events,
        "mmr_root": get_current_root(),
        "total_leaves": mmr_size(),
    }


# ---------------------------------------------------------------------------
# 9. GET /audit/root
# ---------------------------------------------------------------------------

@app.get("/audit/root")
def audit_root():
    integrity_result = verify_audit_integrity()
    return {
        "mmr_root": get_current_root(),
        "leaf_count": mmr_size(),
        "integrity": "INTACT" if integrity_result["intact"] else "TAMPERED",
        "last_check": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# 10. POST /audit/verify-proof
# ---------------------------------------------------------------------------

@app.post("/audit/verify-proof")
def audit_verify_proof(body: ProofVerifyRequest):
    valid = mmr_verify_proof(body.leaf_hash, body.proof, body.root, body.leaf_index)
    proof_size = 0
    if isinstance(body.proof, dict):
        proof_size = len(body.proof.get("siblings", []))
    return {
        "valid": valid,
        "leaf_index": body.leaf_index,
        "proof_size": proof_size,
        "message": "Proof verified successfully" if valid else "Proof verification failed",
    }


# ---------------------------------------------------------------------------
# 11. GET /evidence/{evidence_id}
# ---------------------------------------------------------------------------

@app.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: str, db: Session = Depends(get_db)):
    row = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return {
        "evidence_id": row.evidence_id,
        "intent_id": row.intent_id,
        "decision_id": row.decision_id,
        "ticket_id": row.ticket_id,
        "agent_id": row.agent_id,
        "action": row.action,
        "resource": row.resource,
        "decision": row.decision,
        "reason": row.reason,
        "diff": row.diff,
        "schema_violations": row.schema_violations,
        "injection_findings": row.injection_findings,
        "payload_hash": row.payload_hash,
        "ticket_hash": row.ticket_hash,
        "mmr_leaf_index": row.mmr_leaf_index,
        "mmr_leaf_hash": row.mmr_leaf_hash,
        "mmr_root": row.mmr_root,
        "mmr_proof": row.mmr_proof,
        "mmr_proof_size": row.mmr_proof_size,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


# ---------------------------------------------------------------------------
# 12. GET /evidence/{evidence_id}/pdf
# ---------------------------------------------------------------------------

@app.get("/evidence/{evidence_id}/pdf")
def get_evidence_pdf(evidence_id: str, db: Session = Depends(get_db)):
    row = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Evidence not found")

    evidence_dict = {
        "evidence_id": row.evidence_id,
        "intent_id": row.intent_id,
        "decision_id": row.decision_id,
        "ticket_id": row.ticket_id,
        "agent_id": row.agent_id,
        "action": row.action,
        "resource": row.resource,
        "decision": row.decision,
        "reason": row.reason,
        "diff": row.diff,
        "schema_violations": row.schema_violations,
        "injection_findings": row.injection_findings,
        "payload_hash": row.payload_hash,
        "ticket_hash": row.ticket_hash,
        "mmr_leaf_index": row.mmr_leaf_index,
        "mmr_leaf_hash": row.mmr_leaf_hash,
        "mmr_root": row.mmr_root,
        "mmr_proof": row.mmr_proof,
        "mmr_proof_size": row.mmr_proof_size,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
    pdf_bytes = generate_evidence_pdf(evidence_dict)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=evidence_{evidence_id}.pdf"},
    )


# ---------------------------------------------------------------------------
# 13. GET /evidence/{evidence_id}/proof
# ---------------------------------------------------------------------------

@app.get("/evidence/{evidence_id}/proof")
def get_evidence_proof(evidence_id: str, db: Session = Depends(get_db)):
    row = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return {
        "leaf_hash": row.mmr_leaf_hash,
        "proof": row.mmr_proof,
        "root": row.mmr_root,
        "leaf_index": row.mmr_leaf_index,
    }


# ---------------------------------------------------------------------------
# GET /metrics
# ---------------------------------------------------------------------------

@app.get("/metrics")
def get_metrics(db: Session = Depends(get_db)):
    total = db.query(func.count(VerificationRecord.record_id)).scalar() or 0
    allowed_count = (
        db.query(func.count(VerificationRecord.record_id))
        .filter(VerificationRecord.allowed == True)
        .scalar() or 0
    )
    blocked_count = (
        db.query(func.count(VerificationRecord.record_id))
        .filter(VerificationRecord.allowed == False)
        .scalar() or 0
    )
    injection_blocks = (
        db.query(func.count(VerificationRecord.record_id))
        .filter(VerificationRecord.reason.contains("INJECTION"))
        .scalar() or 0
    )
    schema_blocks = (
        db.query(func.count(VerificationRecord.record_id))
        .filter(VerificationRecord.reason.contains("SCHEMA"))
        .scalar() or 0
    )
    rate_limit_blocks = (
        db.query(func.count(VerificationRecord.record_id))
        .filter(VerificationRecord.reason.contains("RATE_LIMIT"))
        .scalar() or 0
    )
    replay_blocks = (
        db.query(func.count(VerificationRecord.record_id))
        .filter(VerificationRecord.reason.contains("REPLAYED"))
        .scalar() or 0
    )
    return {
        "total_verifications": total,
        "allowed_count": allowed_count,
        "blocked_count": blocked_count,
        "injection_blocks": injection_blocks,
        "schema_blocks": schema_blocks,
        "rate_limit_blocks": rate_limit_blocks,
        "replay_blocks": replay_blocks,
        "mmr_leaf_count": mmr_size(),
        "mmr_root": get_current_root(),
    }


# ---------------------------------------------------------------------------
# DEBUG: POST /debug/tamper-mmr  (only available when DEBUG=true)
# ---------------------------------------------------------------------------

if os.getenv("DEBUG", "").lower() == "true":
    from pydantic import BaseModel as _BaseModel

    class _TamperRequest(_BaseModel):
        leaf_index: int
        new_data: Dict

    @app.post("/debug/tamper-mmr")
    def debug_tamper_mmr(body: _TamperRequest):
        if body.leaf_index < 0 or body.leaf_index >= len(mmr_leaves):
            raise HTTPException(
                status_code=400,
                detail=f"leaf_index {body.leaf_index} out of range (size={len(mmr_leaves)})",
            )
        mmr_leaves[body.leaf_index]["event_data"] = body.new_data
        return {
            "tampered": True,
            "leaf_index": body.leaf_index,
            "new_data": body.new_data,
        }

