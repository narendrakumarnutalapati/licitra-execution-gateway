import pytest

from packages.policy import (
    evaluate_policy,
    reset_counters_for_testing,
)


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_counters():
    reset_counters_for_testing()
    yield
    reset_counters_for_testing()


def _agent(**overrides):
    base = {
        "agent_id": "agent-test-001",
        "is_active": True,
        "allowed_actions": ["send_email"],
        "allowed_resources": ["cfo@company.com"],
        "max_actions_per_hour": 100,
        "max_actions_per_day": 1000,
        "max_daily_budget": 100.0,
        "action_cost_weights": {"send_email": 1.0},
    }
    base.update(overrides)
    return base


def _intent(**overrides):
    base = {
        "action": "send_email",
        "resource": "cfo@company.com",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_allowed_action_passes():
    agent = _agent(allowed_actions=["send_email"], allowed_resources=["cfo@company.com"])
    intent = _intent(action="send_email", resource="cfo@company.com")
    decision = evaluate_policy(agent, intent)
    assert decision.allowed is True


def test_denied_action_blocked():
    agent = _agent(allowed_actions=["send_email"])
    intent = _intent(action="delete_file")
    decision = evaluate_policy(agent, intent)
    assert decision.allowed is False
    assert "ACTION_NOT_ALLOWED" in decision.reason


def test_resource_mismatch_blocked():
    agent = _agent(allowed_resources=["cfo@company.com"])
    intent = _intent(resource="attacker@evil.com")
    decision = evaluate_policy(agent, intent)
    assert decision.allowed is False
    assert "RESOURCE_NOT_ALLOWED" in decision.reason


def test_rate_limit_exceeded():
    agent = _agent(max_actions_per_hour=5, max_actions_per_day=1000)
    intent = _intent()
    for _ in range(5):
        d = evaluate_policy(agent, intent)
        assert d.allowed is True
    sixth = evaluate_policy(agent, intent)
    assert sixth.allowed is False
    assert "RATE_LIMIT_EXCEEDED" in sixth.reason


def test_budget_exceeded():
    agent = _agent(
        max_daily_budget=5.0,
        action_cost_weights={"send_email": 2.0},
        max_actions_per_hour=100,
        max_actions_per_day=1000,
    )
    intent = _intent()
    first = evaluate_policy(agent, intent)
    assert first.allowed is True
    second = evaluate_policy(agent, intent)
    assert second.allowed is True
    third = evaluate_policy(agent, intent)
    assert third.allowed is False
    assert "BUDGET_EXCEEDED" in third.reason


def test_default_deny_no_rules():
    agent = _agent(allowed_actions=[], allowed_resources=[])
    intent = _intent()
    decision = evaluate_policy(agent, intent)
    assert decision.allowed is False


def test_wildcard_resource_matches():
    agent = _agent(allowed_resources=["salesforce/*"])
    intent = _intent(resource="salesforce/contacts/123")
    decision = evaluate_policy(agent, intent)
    assert decision.allowed is True


def test_counter_reset():
    agent = _agent(max_actions_per_hour=2, max_actions_per_day=1000)
    intent = _intent()
    evaluate_policy(agent, intent)
    evaluate_policy(agent, intent)
    blocked = evaluate_policy(agent, intent)
    assert blocked.allowed is False

    reset_counters_for_testing()

    after_reset = evaluate_policy(agent, intent)
    assert after_reset.allowed is True
