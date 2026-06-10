import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

# ---------------------------------------------------------------------------
# Module-level in-memory stores (replaced by DB in Day 7)
# ---------------------------------------------------------------------------
_rate_counters: dict = {}   # key: (agent_id, action) -> {hourly, daily, window_start}
_budget_store: dict = {}    # key: agent_id -> {daily_cost}


def reset_counters_for_testing():
    _rate_counters.clear()
    _budget_store.clear()


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class RateLimitResult:
    passed: bool
    hourly_count: int
    daily_count: int
    limit_hourly: int
    limit_daily: int


@dataclass
class BudgetResult:
    passed: bool
    current_cost: float
    daily_limit: float
    action_cost: float


@dataclass
class PolicyDecision:
    decision_id: str
    allowed: bool
    reason: str
    policy_hash: str
    rate_limit_check: str = "PASS"
    budget_check: str = "PASS"
    current_hourly_count: int = 0
    current_daily_count: int = 0
    current_daily_cost: float = 0.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def resource_matches(resource: str, allowed_resources: list) -> bool:
    if not allowed_resources:
        return False
    for item in allowed_resources:
        if item.endswith("*"):
            prefix = item[:-1]
            if resource.startswith(prefix):
                return True
        elif resource == item:
            return True
    return False


def check_rate_limit(agent: dict, action: str) -> RateLimitResult:
    agent_id = agent["agent_id"]
    key = (agent_id, action)
    now = datetime.now(timezone.utc)

    limit_hourly = agent["max_actions_per_hour"]
    limit_daily = agent["max_actions_per_day"]

    entry = _rate_counters.get(key)
    if entry is None:
        entry = {"hourly_count": 0, "daily_count": 0, "window_start": now}
        _rate_counters[key] = entry

    elapsed = (now - entry["window_start"]).total_seconds()
    if elapsed > 3600:
        entry["hourly_count"] = 0
        entry["window_start"] = now

    hourly = entry["hourly_count"]
    daily = entry["daily_count"]

    if hourly < limit_hourly and daily < limit_daily:
        entry["hourly_count"] += 1
        entry["daily_count"] += 1
        return RateLimitResult(
            passed=True,
            hourly_count=entry["hourly_count"],
            daily_count=entry["daily_count"],
            limit_hourly=limit_hourly,
            limit_daily=limit_daily,
        )

    return RateLimitResult(
        passed=False,
        hourly_count=hourly,
        daily_count=daily,
        limit_hourly=limit_hourly,
        limit_daily=limit_daily,
    )


def check_budget(agent: dict, action: str) -> BudgetResult:
    agent_id = agent["agent_id"]
    daily_limit = agent["max_daily_budget"]
    action_cost = agent.get("action_cost_weights", {}).get(action, 1.0)

    entry = _budget_store.setdefault(agent_id, {"daily_cost": 0.0})
    current_cost = entry["daily_cost"]

    if current_cost + action_cost <= daily_limit:
        entry["daily_cost"] += action_cost
        return BudgetResult(
            passed=True,
            current_cost=entry["daily_cost"],
            daily_limit=daily_limit,
            action_cost=action_cost,
        )

    return BudgetResult(
        passed=False,
        current_cost=current_cost,
        daily_limit=daily_limit,
        action_cost=action_cost,
    )


# ---------------------------------------------------------------------------
# Core policy evaluation
# ---------------------------------------------------------------------------

def _make_decision(
    allowed: bool,
    reason: str,
    rate_limit_check: str = "PASS",
    budget_check: str = "PASS",
    current_hourly_count: int = 0,
    current_daily_count: int = 0,
    current_daily_cost: float = 0.0,
) -> PolicyDecision:
    decision_id = str(uuid4())
    fields_for_hash = {
        "allowed": allowed,
        "budget_check": budget_check,
        "decision_id": decision_id,
        "rate_limit_check": rate_limit_check,
        "reason": reason,
    }
    policy_hash = hashlib.sha256(
        json.dumps(fields_for_hash, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    return PolicyDecision(
        decision_id=decision_id,
        allowed=allowed,
        reason=reason,
        policy_hash=policy_hash,
        rate_limit_check=rate_limit_check,
        budget_check=budget_check,
        current_hourly_count=current_hourly_count,
        current_daily_count=current_daily_count,
        current_daily_cost=current_daily_cost,
    )


def evaluate_policy(agent: dict, intent: dict) -> PolicyDecision:
    if not agent.get("is_active", False):
        return _make_decision(allowed=False, reason="AGENT_INACTIVE")

    if intent["action"] not in agent.get("allowed_actions", []):
        return _make_decision(allowed=False, reason="ACTION_NOT_ALLOWED")

    if not resource_matches(intent["resource"], agent.get("allowed_resources", [])):
        return _make_decision(allowed=False, reason="RESOURCE_NOT_ALLOWED")

    rl = check_rate_limit(agent, intent["action"])
    if not rl.passed:
        return _make_decision(
            allowed=False,
            reason="RATE_LIMIT_EXCEEDED",
            rate_limit_check="FAIL",
            current_hourly_count=rl.hourly_count,
            current_daily_count=rl.daily_count,
        )

    bud = check_budget(agent, intent["action"])
    if not bud.passed:
        return _make_decision(
            allowed=False,
            reason="BUDGET_EXCEEDED",
            budget_check="FAIL",
            current_hourly_count=rl.hourly_count,
            current_daily_count=rl.daily_count,
            current_daily_cost=bud.current_cost,
        )

    return _make_decision(
        allowed=True,
        reason="All policy checks passed",
        rate_limit_check="PASS",
        budget_check="PASS",
        current_hourly_count=rl.hourly_count,
        current_daily_count=rl.daily_count,
        current_daily_cost=bud.current_cost,
    )
