"""Prove properties of an agent's tool policy with the Z3 solver.

A policy is a short YAML file of rules saying when each tool may run:

    rules:
      - tool: IssueRefund
        effect: allow            # or deny
        when: {amount_max: 100}  # optional amount_min / amount_max, inclusive
        require_approval: false

We model one tool call with two unknowns: an integer `amount` (0 or more) and
a boolean `approved`. Z3 then searches every possible value at once. If it
finds a call that breaks a property, that call is a concrete counterexample;
if it finds none, the property is proved for all amounts, not just tested.

This proves properties of the policy as written. It says nothing about
whether the agent, the model or the platform actually enforces the policy.
"""

from dataclasses import dataclass
from pathlib import Path

import yaml
from z3 import And, Bool, BoolVal, Int, Not, Or, Solver, sat

from discover_lite.models import Agent


@dataclass
class Result:
    """The outcome of checking one property."""

    property: str
    proved: bool
    detail: str


def policy_path(policies_dir: Path, agent: Agent) -> Path:
    """Where an agent's policy lives: its file name without .json, plus .yaml."""
    return policies_dir / f"{Path(agent.id).stem}.yaml"


def load_policy(path: Path) -> list[dict]:
    return yaml.safe_load(path.read_text(encoding="utf-8")).get("rules", [])


def _matches(rule: dict, amount) -> object:
    """A Z3 condition: true when `amount` falls inside the rule's range."""
    when = rule.get("when") or {}
    conditions = []
    if "amount_min" in when:
        conditions.append(amount >= when["amount_min"])
    if "amount_max" in when:
        conditions.append(amount <= when["amount_max"])
    # No range at all means the rule covers every amount.
    return And(conditions) if conditions else BoolVal(True)


def _allowed(rules: list[dict], tool: str, amount, approved) -> object:
    """A Z3 condition: true when the policy lets this call run.

    Allowed means some allow rule matches (and, if it requires approval, the
    call is approved) and no deny rule matches. Deny always wins.
    """
    allow = [
        # A rule that requires approval only lets approved calls through.
        And(_matches(r, amount), approved if r.get("require_approval") else BoolVal(True))
        for r in rules
        if r["tool"] == tool and r["effect"] == "allow"
    ]
    deny = [_matches(r, amount) for r in rules if r["tool"] == tool and r["effect"] == "deny"]
    return And(Or(allow) if allow else BoolVal(False), Not(Or(deny)) if deny else BoolVal(True))


def writes_need_approval(agent: Agent, rules: list[dict]) -> Result:
    """Property 1: no allowed call to a write or execute tool skips approval."""
    amount, approved = Int("amount"), Bool("approved")
    for tool in agent.tools:
        if tool.capability not in ("write", "execute"):
            continue
        solver = Solver()
        # Ask Z3: is there a valid call that is allowed but not approved?
        solver.add(amount >= 0, _allowed(rules, tool.name, amount, approved), Not(approved))
        if solver.check() == sat:
            model = solver.model()
            example = model.eval(amount, model_completion=True)
            return Result(
                "Every allowed write needs approval",
                False,
                f"counterexample: {tool.name}(amount={example}, approved=False) is allowed",
            )
    return Result("Every allowed write needs approval", True, "no allowed write runs without approval")


def no_contradictions(rules: list[dict]) -> Result:
    """Property 2: no call matches both an allow rule and a deny rule."""
    amount = Int("amount")
    for allow in (r for r in rules if r["effect"] == "allow"):
        for deny in (r for r in rules if r["effect"] == "deny" and r["tool"] == allow["tool"]):
            solver = Solver()
            solver.add(amount >= 0, _matches(allow, amount), _matches(deny, amount))
            if solver.check() == sat:
                example = solver.model().eval(amount, model_completion=True)
                return Result(
                    "No contradictory rules",
                    False,
                    f"counterexample: {allow['tool']}(amount={example}) matches both an allow and a deny rule",
                )
    return Result("No contradictory rules", True, "no call matches both allow and deny")


def full_coverage(agent: Agent, rules: list[dict]) -> Result:
    """Property 3: every tool the connector found appears in some rule.

    This is a plain set difference; it needs no solver.
    """
    missing = sorted({t.name for t in agent.tools} - {r["tool"] for r in rules})
    if missing:
        return Result("Every tool is covered", False, f"no rule for: {', '.join(missing)}")
    return Result("Every tool is covered", True, "every tool has a rule")


def verify(agent: Agent, rules: list[dict]) -> list[Result]:
    return [writes_need_approval(agent, rules), no_contradictions(rules), full_coverage(agent, rules)]
