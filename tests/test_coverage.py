from discover_lite.coverage import cell, coverage, is_populated
from discover_lite.models import Agent, Tool


def agent(platform, **fields) -> Agent:
    return Agent(id="a", name="a", platform=platform, source_file="x", **fields)


def test_false_counts_as_populated_but_none_does_not():
    assert is_populated(False)
    assert not is_populated(None)
    assert not is_populated("")
    assert not is_populated({})


def test_coverage_counts_per_platform():
    agents = [
        agent("copilot_studio", authentication="None", tools=[Tool(name="t", requires_approval=False)]),
        agent("copilot_studio", tools=[Tool(name="u")]),
        agent("bedrock_agent", guardrail=False),
    ]
    table = coverage(agents)
    assert table["copilot_studio"]["Authentication setting"] == (1, 2)
    assert table["copilot_studio"]["Tool approval setting"] == (1, 2)
    assert table["bedrock_agent"]["Guardrail setting"] == (1, 1)
    assert cell(*table["bedrock_agent"]["Tool approval setting"]) == "-"
