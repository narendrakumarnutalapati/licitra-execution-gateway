from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class AgentRegisterRequest(BaseModel):
    agent_id: str
    agent_name: str
    public_key: str
    owner: str
    allowed_actions: List[str] = []
    allowed_resources: List[str] = []
    output_schemas: Dict[str, Any] = {}
    max_actions_per_hour: int = 100
    max_actions_per_day: int = 500
    max_daily_budget: float = 100.0
    action_cost_weights: Dict[str, float] = {}


class IntentCreateRequest(BaseModel):
    user_id: str
    agent_id: str
    action: str
    resource: str
    purpose: str
    constraints: Dict[str, Any] = {}
    expires_at: str


class PolicyEvaluateRequest(BaseModel):
    intent_id: str
    agent_id: str


class TicketIssueRequest(BaseModel):
    decision_id: str
    agent_id: str
    payload: Dict[str, Any]


class VerifyRequest(BaseModel):
    ticket_id: str
    agent_id: str
    action: str
    resource: str
    payload: Dict[str, Any]


class ProofVerifyRequest(BaseModel):
    leaf_hash: str
    proof: Any
    root: str
    leaf_index: int
