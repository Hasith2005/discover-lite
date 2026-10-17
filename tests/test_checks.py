import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from discover_lite.checks import (
    ALL_CHECKS,
    insecure_remote_server,
    missing_scope,
    no_human_in_loop,
    open_access,
    redact,
    run_all,
    secret_in_config,
    unclassified_tool,
    unpinned_package,
)
from discover_lite.cli import app
from discover_lite.connectors import load_any
from discover_lite.models import Agent, McpServer, Tool

FIXTURES = Path(__file__).parent.parent / "fixtures"

# Synthetic values in well-known key formats (right shape, obviously fake).
FAKE_OPENAI_KEY = "sk-FAKEFAKEFAKEFAKEFAKE1234"
FAKE_GITHUB_TOKEN = "ghp_" + "FAKE" * 9
FAKE_AWS_KEY = "AKIA" + "FAKEFAKEFAKEFAKE"


def mcp_agent(**server_fields) -> Agent:
    """An MCP client agent with one server built from the given fields."""
    return Agent(
        id="test",
        name="test",
        platform="mcp_client",
        source_file="test.json",
        servers=[McpServer(name="srv", **server_fields)],
    )


def copilot_agent(**fields) -> Agent:
    """A Copilot Studio agent with the given fields set."""
    return Agent(id="test", name="test", platform="copilot_studio", source_file="test.json", **fields)


def write_tool(requires_approval) -> Tool:
    return Tool(name="SendEmail", capability="write", requires_approval=requires_approval)


# --- redact -----------------------------------------------------------------


def test_redact_keeps_three_characters():
    assert redact("FAKE_TOKEN_FOR_TESTS") == "FAK****"


# --- secret_in_config -------------------------------------------------------


@pytest.mark.parametrize(
    "fields",
    [
        {"env": {"DB_PASSWORD": "FAKE_PASSWORD_FOR_TESTS"}},
        {"env": {"API_KEY": "FAKE_KEY_FOR_TESTS"}},
        {"headers": {"Authorization": "Bearer FAKE_TOKEN_FOR_TESTS"}},
        # Harmless name, but the value is a known key format.
        {"env": {"OPENAI": FAKE_OPENAI_KEY}},
        {"args": ["--token", FAKE_GITHUB_TOKEN]},
        {"args": [f"--aws={FAKE_AWS_KEY}"]},
    ],
)
def test_secret_in_config_fires(fields):
    findings = secret_in_config(mcp_agent(**fields))
    assert len(findings) == 1
    assert findings[0].severity == "high"


@pytest.mark.parametrize(
    "fields",
    [
        {"env": {"API_KEY": "${API_KEY}"}},
        {"headers": {"Authorization": "Bearer ${TICKETS_TOKEN}"}},
        {"env": {"LOG_LEVEL": "debug"}},
        {"env": {"API_KEY": ""}},
        # A plain word in args is not a key, even after "--token".
        {"args": ["-y", "some-package", "--token", "short"]},
    ],
)
def test_secret_in_config_does_not_fire(fields):
    assert secret_in_config(mcp_agent(**fields)) == []


@pytest.mark.parametrize(
    "fields, secret",
    [
        ({"env": {"DB_PASSWORD": "FAKE_PASSWORD_FOR_TESTS"}}, "FAKE_PASSWORD_FOR_TESTS"),
        ({"headers": {"Authorization": "Bearer FAKE_TOKEN_FOR_TESTS"}}, "FAKE_TOKEN_FOR_TESTS"),
        ({"args": [FAKE_GITHUB_TOKEN]}, FAKE_GITHUB_TOKEN),
    ],
)
def test_secret_never_appears_in_evidence(fields, secret):
    [finding] = secret_in_config(mcp_agent(**fields))
    assert secret not in finding.evidence
    assert redact(secret) in finding.evidence


# --- unpinned_package -------------------------------------------------------


@pytest.mark.parametrize(
    "command, args",
    [
        ("npx", ["-y", "some-package"]),
        ("npx", ["-y", "some-package@latest"]),
        ("npx", ["@scope/some-package@^1.2.0"]),
        ("uvx", ["mcp-server-git"]),
        ("/usr/local/bin/bunx", ["some-package"]),
        ("pnpx", ["some-package@1"]),
    ],
)
def test_unpinned_package_fires(command, args):
    findings = unpinned_package(mcp_agent(command=command, args=args))
    assert len(findings) == 1
    assert findings[0].severity == "medium"


@pytest.mark.parametrize(
    "command, args",
    [
        ("npx", ["-y", "some-package@1.2.3"]),
        ("npx", ["-y", "@scope/some-package@1.2.3"]),
        ("npx", ["some-package@2.0.0-beta.1"]),
        ("uvx", ["mcp-server-git==1.2.3"]),
        # Not a package runner.
        ("node", ["server.js"]),
        # No package argument at all: nothing to judge.
        ("npx", ["-y"]),
    ],
)
def test_unpinned_package_does_not_fire(command, args):
    assert unpinned_package(mcp_agent(command=command, args=args)) == []


# --- insecure_remote_server -------------------------------------------------


def test_plain_http_fires_high_and_low():
    findings = insecure_remote_server(mcp_agent(url="http://wiki.example.com/mcp"))
    assert sorted(f.severity for f in findings) == ["high", "low"]


def test_https_without_authorization_fires_low():
    findings = insecure_remote_server(mcp_agent(url="https://api.example.com/mcp"))
    assert [f.severity for f in findings] == ["low"]


@pytest.mark.parametrize(
    "fields",
    [
        {"url": "https://api.example.com/mcp", "headers": {"Authorization": "Bearer ${TOKEN}"}},
        # Header names are case-insensitive.
        {"url": "https://api.example.com/mcp", "headers": {"authorization": "Bearer ${TOKEN}"}},
        {"url": "http://localhost:8080/mcp"},
        {"url": "http://127.0.0.1:8080/mcp"},
        # Local server with no url.
        {"command": "node", "args": ["server.js"]},
    ],
)
def test_insecure_remote_server_does_not_fire(fields):
    assert insecure_remote_server(mcp_agent(**fields)) == []


# --- missing_scope ----------------------------------------------------------


@pytest.mark.parametrize("instructions", ["Help employees.", "", "   "])
def test_missing_scope_fires(instructions):
    findings = missing_scope(copilot_agent(instructions=instructions))
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_missing_scope_does_not_fire_for_detailed_instructions():
    instructions = "Answer questions about the HR leave policy only. Refuse anything else politely."
    assert missing_scope(copilot_agent(instructions=instructions)) == []


def test_missing_scope_does_not_fire_when_platform_does_not_say():
    assert missing_scope(copilot_agent(instructions=None)) == []


def test_missing_scope_skips_mcp_clients():
    assert missing_scope(mcp_agent(command="node")) == []


# --- no_human_in_loop -------------------------------------------------------


@pytest.mark.parametrize("capability", ["write", "execute"])
def test_no_human_in_loop_fires(capability):
    tool = Tool(name="DoThing", capability=capability, requires_approval=False)
    findings = no_human_in_loop(copilot_agent(tools=[tool]))
    assert len(findings) == 1
    assert findings[0].severity == "high"


@pytest.mark.parametrize(
    "tool",
    [
        write_tool(requires_approval=True),
        Tool(name="GetFile", capability="read", requires_approval=False),
        Tool(name="Mystery", capability="unknown", requires_approval=False),
    ],
)
def test_no_human_in_loop_does_not_fire(tool):
    assert no_human_in_loop(copilot_agent(tools=[tool])) == []


def test_no_human_in_loop_does_not_fire_when_approval_is_unknown():
    assert no_human_in_loop(copilot_agent(tools=[write_tool(requires_approval=None)])) == []


# --- open_access ------------------------------------------------------------


def test_open_access_no_authentication_is_high():
    findings = open_access(copilot_agent(authentication="None"))
    assert [f.severity for f in findings] == ["high"]


def test_open_access_shared_org_wide_is_medium():
    findings = open_access(copilot_agent(shared_org_wide=True))
    assert [f.severity for f in findings] == ["medium"]


@pytest.mark.parametrize(
    "fields",
    [
        {"authentication": "Microsoft Entra", "shared_org_wide": False},
        # Platform does not say: neither setting fires.
        {"authentication": None, "shared_org_wide": None},
    ],
)
def test_open_access_does_not_fire(fields):
    assert open_access(copilot_agent(**fields)) == []


# --- unclassified_tool ------------------------------------------------------


def test_unclassified_tool_fires():
    tool = Tool(name="EscalateCase", capability="unknown", requires_approval=False)
    findings = unclassified_tool(copilot_agent(tools=[tool]))
    assert [f.severity for f in findings] == ["low"]


@pytest.mark.parametrize(
    "tool",
    [
        Tool(name="EscalateCase", capability="unknown", requires_approval=True),
        # Platform does not say whether approval is needed: do not fire.
        Tool(name="EscalateCase", capability="unknown", requires_approval=None),
        # Classified tools are handled by other checks.
        Tool(name="GetFile", capability="read", requires_approval=False),
        write_tool(requires_approval=False),
    ],
)
def test_unclassified_tool_does_not_fire(tool):
    assert unclassified_tool(copilot_agent(tools=[tool])) == []


# --- end to end -------------------------------------------------------------


def test_fixtures_trigger_every_check():
    fired = set()
    for path in FIXTURES.glob("*.json"):
        fired |= {f.check_id for f in run_all(load_any(path))}
    assert fired == {check.__name__ for check in ALL_CHECKS}


@pytest.mark.parametrize("extra_args", [[], ["--json"]])
def test_cli_never_prints_fixture_secret(extra_args):
    result = CliRunner().invoke(app, [str(FIXTURES), *extra_args])
    assert result.exit_code == 0
    assert "FAKE_DB_PASSWORD_FOR_TESTS" not in result.output


def test_cli_json_output():
    result = CliRunner().invoke(app, [str(FIXTURES), "--json"])
    data = json.loads(result.output)
    names = {entry["agent"]["name"] for entry in data}
    assert names == {"claude_desktop_config.json", "HR Helper"}
