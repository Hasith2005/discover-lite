import pytest
from cvss import CVSS4

from discover_lite.aivss import aivss, band, factors, score_agent
from discover_lite.mappings import load_mappings
from discover_lite.models import Agent, Finding, McpServer, Tool


# --- the formula, against the spec's own worked examples (section 3.6) ---------


@pytest.mark.parametrize(
    "cvss_base, factor_sum, expected",
    [
        (9.4, 9.0, 9.9),  # 3.6.1: AARS 0.5238, raw 9.9238
        (7.1, 8.0, 9.4),  # 3.6.3: raw 9.3504
        (9.4, 9.5, 10.0),  # 3.6.4: raw 9.9529
        (5.8, 7.5, 8.9),  # 3.6.6: raw 8.8555
        (6.9, 7.5, 9.2),  # 3.6.7: raw 9.15525
        (9.3, 6.5, 9.7),  # 3.6.8: raw 9.74135
        (5.3, 6.5, 8.3),  # 3.6.9: raw 8.26335
        (2.1, 6.5, 7.1),  # 3.6.10: a low CVSS raised by the agentic context
    ],
)
def test_formula_matches_the_spec_examples(cvss_base, factor_sum, expected):
    assert aivss(cvss_base, factor_sum)[1] == expected


def test_no_agentic_factors_leaves_cvss_unchanged():
    assert aivss(7.0, 0.0) == (0.0, 7.0)


@pytest.mark.parametrize(
    "score, expected",
    [(None, "None"), (0.0, "None"), (3.9, "Low"), (4.0, "Medium"), (6.9, "Medium"), (7.0, "High"), (9.0, "Critical")],
)
def test_bands(score, expected):
    assert band(score) == expected


# --- CVSS vectors in the mappings ---------------------------------------------


def test_every_security_check_has_valid_cvss_vectors():
    for check, mapping in load_mappings().items():
        vectors = mapping.get("cvss_v4", {})
        if mapping["category"] == "quality":
            assert not vectors, check
            continue
        assert vectors and mapping["cvss_why"], check
        for severity, vector in vectors.items():
            assert severity in ("high", "medium", "low")
            assert 0 < CVSS4(vector).base_score <= 10, (check, vector)


# --- factors from the config ---------------------------------------------------


def by_name(agent: Agent) -> dict:
    return {f.name: f for f in factors(agent)}


def agent(**fields) -> Agent:
    return Agent(id="a", name="a", platform="copilot_studio", source_file="x", **fields)


def test_factors_are_in_the_spec_order():
    names = [f.name for f in factors(agent())]
    assert names == [
        "Autonomy", "Tools", "Language", "Context", "Non-Determinism",
        "Opacity", "Persistence", "Identity", "Multi-Agent", "Self-Mod",
    ]


def test_unapproved_write_is_full_autonomy():
    f = by_name(agent(tools=[Tool(name="IssueRefund", capability="write", requires_approval=False)]))
    assert (f["Autonomy"].value, f["Autonomy"].assumed) == (1.0, False)
    assert f["Tools"].value == 0.5
    assert f["Language"].value == 1.0
    assert f["Self-Mod"].value == 0.0


def test_approved_writes_are_no_autonomy():
    f = by_name(agent(tools=[Tool(name="IssueRefund", capability="write", requires_approval=True)]))
    assert f["Autonomy"].value == 0.0


def test_unknown_approval_is_not_shown():
    # None means the platform does not say: never scored as safe or unsafe.
    assert by_name(agent(tools=[Tool(name="IssueRefund", capability="write")]))["Autonomy"].assumed


def test_code_execution_is_full_tools_and_self_mod():
    f = by_name(agent(tools=[Tool(name="CodeInterpreter", capability="execute", requires_approval=False)]))
    assert f["Tools"].value == 1.0 and f["Self-Mod"].value == 1.0


def test_mcp_servers_do_not_show_their_tools():
    f = by_name(Agent(id="m", name="m", platform="mcp_client", source_file="x", servers=[McpServer(name="git", command="uvx")]))
    assert f["Tools"].assumed and f["Self-Mod"].assumed and f["Autonomy"].assumed


def test_guardrail_and_knowledge_are_read_from_the_config():
    f = by_name(agent(guardrail=True, untrusted_knowledge=True))
    assert f["Non-Determinism"].value == 0.5
    assert f["Context"].value == 1.0
    assert by_name(agent(guardrail=False))["Non-Determinism"].value == 1.0


# --- agent scores --------------------------------------------------------------


def finding(check: str, severity: str) -> Finding:
    return Finding(check_id=check, agent_id="a", severity=severity, evidence="", recommendation="")


def test_agent_takes_its_highest_finding_as_a_range():
    a = agent(tools=[Tool(name="IssueRefund", capability="write", requires_approval=False)])
    risk = score_agent(a, [finding("no_human_in_loop", "high"), finding("missing_scope", "medium")])
    assert risk.score == max(s.score for s in risk.findings)
    assert risk.low == max(s.low for s in risk.findings)
    assert risk.low < risk.score  # Five factors are not shown in the config.
    assert risk.text == f"{risk.low}-{risk.score} ({risk.band if risk.band == band(risk.low) else band(risk.low) + '-' + risk.band})"


def test_quality_findings_are_not_scored():
    risk = score_agent(agent(), [finding("topic_overlap", "medium")])
    assert risk.score is None and risk.findings == []
    assert risk.text == "no security findings"
