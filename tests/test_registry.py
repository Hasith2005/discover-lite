"""Tests for the MCP Registry connector, using a trimmed sample of real data."""

from pathlib import Path

import pytest

from discover_lite.checks import insecure_remote_server, run_all, unpinned_package
from discover_lite.connectors import load_agents
from discover_lite.connectors.mcp_registry import package_server, parse_page
from discover_lite.models import Agent, McpServer

SAMPLE = Path(__file__).parent / "data" / "registry_sample.json"


def registry_agent(*servers: McpServer) -> Agent:
    return Agent(
        id="test", name="test", platform="mcp_registry", source_file="page.json", servers=list(servers)
    )


def test_sample_parses_latest_versions_only():
    agents = load_agents(SAMPLE)
    # The sample has three entries; one is an old version and is skipped.
    assert [a.id for a in agents] == ["ai.2kw/mcp-server", "ac.inference.sh/mcp"]

    package_entry, remote_entry = agents
    assert package_entry.platform == "mcp_registry"
    assert package_entry.servers == [
        McpServer(
            name="@2kw/ai-mcp-server",
            command="npx",
            args=["@2kw/ai-mcp-server@6.3.0"],
            registry_type="npm",
            # Only the variable marked isSecret.
            declared_secrets=["AI_2KW_API_KEY"],
        )
    ]
    assert remote_entry.servers == [
        McpServer(name="ac.inference.sh/mcp (remote 1)", url="https://api.inference.sh/mcp")
    ]


def test_sample_has_no_findings():
    # Pinned package, HTTPS remote, and a declared secret, which is not a finding.
    assert [f for a in load_agents(SAMPLE) for f in run_all(a)] == []


def test_entry_without_is_latest_flag_is_kept():
    page = {"servers": [{"server": {"name": "x/y"}}], "metadata": {}}
    assert [a.id for a in parse_page(page, Path("page.json"))] == ["x/y"]


@pytest.mark.parametrize(
    "registry_type, version, expect_unpinned",
    [
        ("npm", "1.2.3", False),
        ("npm", "latest", True),
        ("npm", None, True),
        ("npm", "", True),
        ("npm", "^1.2.0", True),
        ("pypi", "1.2.3", False),
        ("pypi", "latest", True),
        ("pypi", ">=1.0", True),
    ],
)
def test_registry_pinning_rules(registry_type, version, expect_unpinned):
    package = {"registryType": registry_type, "identifier": "some-server", "version": version}
    findings = unpinned_package(registry_agent(package_server(package)))
    assert bool(findings) == expect_unpinned


def test_runtime_hint_overrides_default_runner():
    package = {"registryType": "npm", "identifier": "pkg", "version": "1.0.0", "runtimeHint": "bunx"}
    assert package_server(package).command == "bunx"


def test_registry_plain_http_is_high_and_missing_auth_is_skipped():
    agent = registry_agent(McpServer(name="r", url="http://api.example.com/mcp"))
    assert [f.severity for f in insecure_remote_server(agent)] == ["high"]
    https = registry_agent(McpServer(name="r", url="https://api.example.com/mcp"))
    assert insecure_remote_server(https) == []
