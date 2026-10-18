"""An explainable risk score for each agent, from 0 to 100.

Each failed check adds its weight. One pair of checks adds a bonus when both
fail, because together they are worse than apart. The total is capped at 100.

To show where every point comes from, the score is split between the failed
checks using exact Shapley values (from game theory): each check gets its
average extra contribution over every order in which the checks could have
been added. The parts always add up to the score, and a bonus shared by two
checks is split fairly between them.
"""

from itertools import combinations
from math import factorial

from discover_lite.models import Finding

# Points each check adds when it fails. A check counts once per agent, however
# many findings it produced.
WEIGHTS = {
    "secret_in_config": 30,
    "no_human_in_loop": 25,
    "prompt_injection_exposure": 25,
    "open_access": 20,
    "insecure_remote_server": 15,
    "unpinned_package": 15,
    "broad_filesystem_access": 15,
    "missing_scope": 10,
    "topic_overlap": 10,
    "no_guardrail": 10,
    "unclassified_tool": 5,
}

# Untrusted content plus an action tool with no approval is the full breach
# path: an injected instruction can act with nobody checking.
INTERACTION = ("prompt_injection_exposure", "no_human_in_loop")
INTERACTION_BONUS = 15

MAX_SCORE = 100


def score(failed: set[str]) -> float:
    """The risk score for a set of failed check ids."""
    total = sum(WEIGHTS[check] for check in failed)
    if all(check in failed for check in INTERACTION):
        total += INTERACTION_BONUS
    return min(total, MAX_SCORE)


def shapley(failed: set[str]) -> dict[str, float]:
    """Each failed check's exact share of the score.

    For each check, look at every subset of the other failed checks and ask
    how much adding this check raises the score. The Shapley value is the
    weighted average of those raises, where a subset of size k gets weight
    k! (n - k - 1)! / n!, the share of orderings in which exactly that subset
    comes first. With up to 11 checks this is at most 1,024 subsets each.
    """
    checks = sorted(failed)
    n = len(checks)
    values = {}
    for check in checks:
        others = [c for c in checks if c != check]
        value = 0.0
        for k in range(len(others) + 1):
            weight = factorial(k) * factorial(n - k - 1) / factorial(n)
            for subset in combinations(others, k):
                before = set(subset)
                value += weight * (score(before | {check}) - score(before))
        values[check] = value
    return values


def score_agent(findings: list[Finding]) -> tuple[float, dict[str, float]]:
    """The score and its breakdown for one agent's findings."""
    failed = {f.check_id for f in findings}
    return score(failed), shapley(failed)
