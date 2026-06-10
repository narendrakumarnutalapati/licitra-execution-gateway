from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, Numeric,
    String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSON

try:
    from apps.api.database import Base
except ImportError:
    from database import Base  # type: ignore


def _now():
    return datetime.now(timezone.utc)


class Agent(Base):
    __tablename__ = "agents"

    agent_id = Column(String, primary_key=True)
    agent_name = Column(String, nullable=False)
    public_key = Column(Text, nullable=False)
    owner = Column(String, nullable=False)
    allowed_actions = Column(JSON, nullable=False, default=list)
    allowed_resources = Column(JSON, nullable=False, default=list)
    output_schemas = Column(JSON, nullable=False, default=dict)
    max_actions_per_hour = Column(Integer, nullable=False, default=100)
    max_actions_per_day = Column(Integer, nullable=False, default=500)
    max_daily_budget = Column(Numeric, nullable=False, default=100.0)
    action_cost_weights = Column(JSON, nullable=False, default=dict)
    is_active = Column(Boolean, nullable=False, default=True)
    registered_at = Column(DateTime(timezone=True), default=_now)


class Intent(Base):
    __tablename__ = "intents"

    intent_id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False)
    agent_id = Column(String, ForeignKey("agents.agent_id"), nullable=False)
    action = Column(String, nullable=False)
    resource = Column(Text, nullable=False)
    purpose = Column(Text, nullable=False)
    constraints = Column(JSON, default=dict)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    injection_scan_result = Column(String, default="PASS")
    injection_patterns_found = Column(JSON, nullable=True)
    status = Column(String, default="PENDING")
    created_at = Column(DateTime(timezone=True), default=_now)


class PolicyDecision(Base):
    __tablename__ = "policy_decisions"

    decision_id = Column(String, primary_key=True)
    intent_id = Column(String, ForeignKey("intents.intent_id"), nullable=False)
    agent_id = Column(String, ForeignKey("agents.agent_id"), nullable=False)
    allowed = Column(Boolean, nullable=False)
    reason = Column(Text, nullable=False)
    policy_hash = Column(String, nullable=False)
    rate_limit_check = Column(String, default="PASS")
    budget_check = Column(String, default="PASS")
    current_hourly_count = Column(Integer, default=0)
    current_daily_count = Column(Integer, default=0)
    current_daily_cost = Column(Numeric, default=0.0)
    evaluated_at = Column(DateTime(timezone=True), default=_now)


class ExecutionTicket(Base):
    __tablename__ = "execution_tickets"

    ticket_id = Column(String, primary_key=True)
    decision_id = Column(String, ForeignKey("policy_decisions.decision_id"), nullable=False)
    agent_id = Column(String, ForeignKey("agents.agent_id"), nullable=False)
    action = Column(String, nullable=False)
    resource = Column(Text, nullable=False)
    purpose = Column(Text, nullable=False)
    constraints_hash = Column(String, nullable=False)
    payload_hash = Column(String, nullable=False)
    output_schema_hash = Column(String, nullable=False)
    expires_at = Column(String, nullable=False)
    jti = Column(String, unique=True, nullable=False)
    issuer_signature = Column(Text, nullable=False)
    status = Column(String, default="ACTIVE")
    issued_at = Column(String, default=None)


class VerificationRecord(Base):
    __tablename__ = "verification_records"

    record_id = Column(String, primary_key=True)
    ticket_id = Column(String, ForeignKey("execution_tickets.ticket_id"), nullable=True)
    agent_id = Column(String, ForeignKey("agents.agent_id"), nullable=True)
    action_submitted = Column(String, nullable=False)
    resource_submitted = Column(Text, nullable=False)
    payload_hash_submitted = Column(String, nullable=False)
    allowed = Column(Boolean, nullable=False)
    reason = Column(String, nullable=False)
    checks_passed = Column(JSON, nullable=False)
    diff = Column(JSON, nullable=True)
    schema_violations = Column(JSON, nullable=True)
    injection_recheck = Column(String, default="PASS")
    evidence_id = Column(String, nullable=True)
    verified_at = Column(DateTime(timezone=True), default=_now)


class Evidence(Base):
    __tablename__ = "evidence"

    evidence_id = Column(String, primary_key=True)
    intent_id = Column(String, nullable=False)
    decision_id = Column(String, nullable=False)
    ticket_id = Column(String, nullable=False)
    agent_id = Column(String, nullable=False)
    action = Column(String, nullable=False)
    resource = Column(Text, nullable=False)
    decision = Column(String, nullable=False)
    reason = Column(Text, nullable=False)
    diff = Column(JSON, nullable=True)
    schema_violations = Column(JSON, nullable=True)
    injection_findings = Column(JSON, nullable=True)
    payload_hash = Column(String, nullable=False)
    ticket_hash = Column(String, nullable=False)
    mmr_leaf_index = Column(Integer, nullable=False)
    mmr_leaf_hash = Column(String, nullable=False)
    mmr_root = Column(String, nullable=False)
    mmr_proof = Column(JSON, nullable=False)
    mmr_proof_size = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_now)
