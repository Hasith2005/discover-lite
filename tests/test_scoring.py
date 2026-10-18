import pytest

from discover_lite.checks import ALL_CHECKS
from discover_lite.scoring import INTERACTION_BONUS, MAX_SCORE, WEIGHTS, score, shapley


def test_every_check_has_a_weight():
    assert set(WEIGHTS) == {check.__name__ for check in ALL_CHECKS}


def test_no_failed_checks_scores_zero():
    assert score(set()) == 0
    assert shapley(set()) == {}


def test_additive_case_gives_each_check_its_weight():
    failed = {"secret_in_config", "unpinned_package", "missing_scope"}
    assert score(failed) == 30 + 15 + 10
    assert shapley(failed) == pytest.approx({"secret_in_config": 30, "unpinned_package": 15, "missing_scope": 10})


def test_interaction_bonus_is_split_equally():
    failed = {"prompt_injection_exposure", "no_human_in_loop", "missing_scope"}
    assert score(failed) == 25 + 25 + 10 + INTERACTION_BONUS
    values = shapley(failed)
    # Each check in the pair gets its weight plus half the bonus.
    assert values["prompt_injection_exposure"] == pytest.approx(25 + INTERACTION_BONUS / 2)
    assert values["no_human_in_loop"] == pytest.approx(25 + INTERACTION_BONUS / 2)
    assert values["missing_scope"] == pytest.approx(10)


@pytest.mark.parametrize(
    "failed",
    [
        {"secret_in_config"},
        {"prompt_injection_exposure", "no_human_in_loop"},
        # Over the cap: the parts still add up to exactly 100.
        set(WEIGHTS),
    ],
)
def test_shapley_values_sum_to_score(failed):
    assert sum(shapley(failed).values()) == pytest.approx(score(failed))


def test_score_is_capped():
    assert score(set(WEIGHTS)) == MAX_SCORE
