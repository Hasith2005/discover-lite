from pathlib import Path

import pytest

from discover_lite.connectors import load_any
from discover_lite.models import Agent, Tool
from discover_lite.verifier import (
    full_coverage,
    load_policy,
    no_contradictions,
    policy_path,
    verify,
    writes_need_approval,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"
POLICIES = FIXTURES / "policies"


def refund_agent() -> Agent:
    tools = [Tool(name="IssueRefund", capability="write"), Tool(name="LookupOrder", capability="read")]
    return Agent(id="refunds.json", name="refunds", platform="copilot_studio", source_file="x", tools=tools)


# --- property 1: every allowed write needs approval ---------------------------


def test_small_refunds_without_approval_are_caught():
    rules = [
        {"tool": "IssueRefund", "effect": "allow", "when": {"amount_max": 100}, "require_approval": False},
        {"tool": "IssueRefund", "effect": "allow", "when": {"amount_min": 101}, "require_approval": True},
    ]
    result = writes_need_approval(refund_agent(), rules)
    assert not result.proved
    # The counterexample is a real call inside the unapproved range.
    amount = int(result.detail.split("amount=")[1].split(",")[0])
    assert 0 <= amount <= 100


def test_approval_on_every_range_is_proved():
    rules = [{"tool": "IssueRefund", "effect": "allow", "require_approval": True}]
    assert writes_need_approval(refund_agent(), rules).proved


def test_denied_range_needs_no_approval():
    # Small refunds are allowed without approval, but a deny rule blocks them.
    rules = [
        {"tool": "IssueRefund", "effect": "allow", "when": {"amount_max": 100}, "require_approval": False},
        {"tool": "IssueRefund", "effect": "deny", "when": {"amount_max": 100}},
    ]
    assert writes_need_approval(refund_agent(), rules).proved


def test_read_tools_need_no_approval():
    rules = [{"tool": "LookupOrder", "effect": "allow", "require_approval": False}]
    assert writes_need_approval(refund_agent(), rules).proved


# --- property 2: no contradictions --------------------------------------------


def test_overlapping_allow_and_deny_are_caught():
    rules = [
        {"tool": "IssueRefund", "effect": "allow", "when": {"amount_min": 101}},
        {"tool": "IssueRefund", "effect": "deny", "when": {"amount_min": 5000}},
    ]
    result = no_contradictions(rules)
    assert not result.proved
    assert "amount=" in result.detail


def test_touching_ranges_do_not_overlap():
    rules = [
        {"tool": "IssueRefund", "effect": "allow", "when": {"amount_max": 10000}},
        {"tool": "IssueRefund", "effect": "deny", "when": {"amount_min": 10001}},
    ]
    assert no_contradictions(rules).proved


# --- property 3: full coverage --------------------------------------------------


def test_tool_with_no_rule_is_reported():
    rules = [{"tool": "IssueRefund", "effect": "allow", "require_approval": True}]
    result = full_coverage(refund_agent(), rules)
    assert not result.proved
    assert "LookupOrder" in result.detail


def test_every_tool_with_a_rule_is_proved():
    rules = [{"tool": "IssueRefund", "effect": "allow"}, {"tool": "LookupOrder", "effect": "allow"}]
    assert full_coverage(refund_agent(), rules).proved


# --- fixtures -------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture, expected",
    [
        ("copilot_refunds_bot.json", [False, False, True]),
        ("copilot_expenses.json", [True, True, True]),
        ("bedrock_travel_agent.json", [True, True, False]),
    ],
)
def test_fixture_policies(fixture, expected):
    agent = load_any(FIXTURES / fixture)
    results = verify(agent, load_policy(policy_path(POLICIES, agent)))
    assert [r.proved for r in results] == expected
