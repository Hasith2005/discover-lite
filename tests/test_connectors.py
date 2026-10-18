from pathlib import Path

import pytest

from discover_lite.connectors import load_any
from discover_lite.connectors.copilot_export import classify, infer_capability
from discover_lite.models import Agent, McpServer, Tool

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_mcp_config_fixture():
    path = FIXTURES / "claude_desktop_config.json"
    assert load_any(path) == Agent(
        id="claude_desktop_config.json",
        name="claude_desktop_config.json",
        platform="mcp_client",
        source_file=str(path),
        servers=[
            McpServer(
                name="postgres",
                command="npx",
                args=["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/app"],
                env={"DB_PASSWORD": "FAKE_DB_PASSWORD_7f3a9c2e81b4"},
            ),
            McpServer(
                name="filesystem",
                command="npx",
                args=["-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/home/demo/projects"],
            ),
            McpServer(
                name="tickets",
                url="https://tickets.example.com/mcp",
                headers={"Authorization": "Bearer ${TICKETS_TOKEN}"},
            ),
            McpServer(name="legacy-wiki", url="http://wiki.example.com/mcp"),
        ],
    )


def test_copilot_export_fixture():
    path = FIXTURES / "copilot_hr_helper.json"
    assert load_any(path) == Agent(
        id="copilot_hr_helper.json",
        name="HR Helper",
        platform="copilot_studio",
        source_file=str(path),
        instructions="Help employees.",
        # GetFileContent is usedAs Knowledge, so it is not a tool.
        tools=[
            Tool(name="SendEmailV2", capability="write", requires_approval=False),
            # No requiresEndUserConsent key, so approval stays None.
            Tool(name="GetMyProfile", capability="read", requires_approval=None),
            # "Escalate" is in neither word list.
            Tool(name="EscalateCase", capability="unknown", requires_approval=False),
        ],
        untrusted_knowledge=True,
        authentication="None",
        shared_org_wide=True,
        topics={
            "reset_password": ["reset my password", "I forgot my password", "change my password"],
            "unlock_account": [
                "unlock my account",
                "my account is locked",
                "locked out after too many password attempts",
            ],
        },
    )


@pytest.mark.parametrize(
    "operation_id, expected",
    [
        ("SendEmailV2", "write"),
        ("CreateItem", "write"),
        ("DeleteFile", "write"),
        ("TransferFunds", "write"),
        ("RemoveUser", "write"),
        ("send_email", "write"),
        # A write word wins over a read word: fail closed.
        ("UpdateReadStatus", "write"),
        ("GetMyProfile", "read"),
        ("ListRows", "read"),
        ("LookUpRecord", "read"),
        # "Address" contains "add" but is not the word "add".
        ("GetAddress", "read"),
        # No known word: unknown, never read.
        ("EscalateCase", "unknown"),
        ("Foo", "unknown"),
    ],
)
def test_infer_capability(operation_id, expected):
    assert infer_capability(operation_id) == expected


@pytest.mark.parametrize(
    "content",
    [
        "not json at all",
        "[1, 2, 3]",
        '{"something": "else"}',
        # Right outer shape, but "args" has the wrong type.
        '{"mcpServers": {"x": {"command": "npx", "args": "oops"}}}',
    ],
)
def test_load_any_returns_none_for_unrecognised(tmp_path, content):
    path = tmp_path / "config.json"
    path.write_text(content)
    assert load_any(path) is None


@pytest.mark.parametrize(
    "operation_id, method, expected",
    [
        # The method decides when the name says nothing.
        ("EscalateCase", "POST", "write"),
        ("EscalateCase", "DELETE", "write"),
        ("EscalateCase", "GET", "read"),
        ("EscalateCase", "get", "read"),
        # Either source saying "write" wins: fail closed.
        ("GetReport", "POST", "write"),
        ("DeleteFile", "GET", "write"),
        # No method, or one we do not know: the name decides.
        ("EscalateCase", None, "unknown"),
        ("EscalateCase", "TRACE", "unknown"),
        ("GetReport", None, "read"),
    ],
)
def test_classify(operation_id, method, expected):
    assert classify(operation_id, method) == expected


def test_vscode_servers_format():
    agent = load_any(FIXTURES / "vscode" / "mcp.json")
    assert agent.platform == "mcp_client"
    assert [s.name for s in agent.servers] == ["filesystem", "git", "notion"]
    # The secret comes from a VS Code input, so the value is a reference.
    assert agent.servers[2].env == {"NOTION_TOKEN": "${input:notion_key}"}


def test_servers_key_that_is_not_a_client_config_is_ignored(tmp_path):
    # A "servers" mapping whose entries have no command or url is something else.
    path = tmp_path / "game.json"
    path.write_text('{"servers": {"eu-1": {"region": "eu", "players": 64}}}')
    assert load_any(path) is None


def test_bedrock_agent_fixture():
    agent = load_any(FIXTURES / "bedrock_travel_agent.json")
    assert agent.platform == "bedrock_agent"
    assert agent.name == "Travel Booker"
    assert agent.guardrail is False
    tools = {t.name: (t.capability, t.requires_approval) for t in agent.tools}
    assert tools == {
        "search_flights": ("read", None),
        # "book" is in neither word list, so it stays unknown.
        "book_flight": ("unknown", True),
        "cancel_booking": ("write", False),
        # From the inline OpenAPI schema: the HTTP method decides.
        "searchHotels": ("read", None),
        "reserveHotel": ("write", None),
        "CodeInterpreter": ("execute", None),
    }
    # The disabled action group adds no tools.
    assert "delete_expense" not in tools


def test_bedrock_guardrail_present():
    agent = load_any(FIXTURES / "bedrock_claims_agent.json")
    assert agent.guardrail is True
    # Access is governed by IAM, which GetAgent does not show.
    assert agent.authentication is None and agent.shared_org_wide is None


def _parse(tmp_path, config: dict):
    import json

    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    return load_any(path)


def test_windsurf_server_url(tmp_path):
    agent = _parse(tmp_path, {"mcpServers": {"remote": {"serverUrl": "http://mcp.example.com/sse"}}})
    assert agent.servers[0].url == "http://mcp.example.com/sse"


def test_cmd_wrapper_is_unwrapped(tmp_path):
    agent = _parse(tmp_path, {"mcpServers": {"s": {"command": "cmd", "args": ["/c", "npx", "-y", "pkg"]}}})
    assert (agent.servers[0].command, agent.servers[0].args) == ("npx", ["-y", "pkg"])


def test_cmd_shell_line_is_left_alone(tmp_path):
    args = ["/c", "cd app && python server.py"]
    agent = _parse(tmp_path, {"mcpServers": {"s": {"command": "cmd", "args": args}}})
    assert (agent.servers[0].command, agent.servers[0].args) == ("cmd", args)


def test_cline_always_allow_becomes_unapproved_tools(tmp_path):
    entry = {"command": "npx", "args": ["pkg@1.0.0"], "alwaysAllow": ["read_file", "write_file", 7]}
    agent = _parse(tmp_path, {"mcpServers": {"fs": entry}})
    assert agent.tools == [
        Tool(name="read_file", capability="read", requires_approval=False),
        Tool(name="write_file", capability="write", requires_approval=False),
    ]


def test_dot_file_config_is_named_after_its_folder():
    # Every project's .mcp.json has the same name; its folder says which one.
    assert load_any(Path(__file__).parent.parent / "fixtures" / "web-app" / ".mcp.json").name == "web-app/.mcp.json"
