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
        ],
    )


def test_copilot_export_fixture():
    path = FIXTURES / "copilot_hr_helper.json"
    assert load_any(path) == Agent(
        id="copilot_hr_helper.json",
        name="HR Helper",
        platform="copilot_studio",
        source_file=str(path),
        # The inventory holds no instructions or topics, so they stay unset.
        # GetFileContent is usedAs Knowledge, so it is not a tool.
        tools=[
            Tool(name="SendEmailV2", capability="write", requires_approval=False),
            # No requiresEndUserConsent key, so approval stays None.
            # "My" and "Profile" are in neither word list.
            Tool(name="MyProfile_V2", capability="unknown", requires_approval=None),
            # "Escalate" is in neither word list.
            Tool(name="EscalateCase", capability="unknown", requires_approval=False),
        ],
        untrusted_knowledge=True,
        authentication="None",
        shared_org_wide=True,
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


def test_foundry_agent_object_fixture():
    # A saved "get agent" response: the newest version sits under versions.latest.
    agent = load_any(FIXTURES / "foundry_support_agent.json")
    assert agent.platform == "foundry_agent"
    assert agent.name == "support-agent"
    assert agent.servers == [McpServer(name="tickets", url="https://tickets.example.com/mcp")]
    # web_search is untrusted content; without rai_config the definition does
    # not say whether a filter applies (the model deployment may have one).
    assert agent.untrusted_knowledge is True
    assert agent.guardrail is None
    assert agent.authentication is None and agent.shared_org_wide is None
    tools = {t.name: (t.capability, t.requires_approval) for t in agent.tools}
    assert tools == {
        # MCP tools with require_approval "never".
        "search_tickets": ("read", False),
        "close_ticket": ("write", False),
        # From the OpenAPI spec: the HTTP method decides.
        "getOrder": ("read", None),
        "createRefund": ("write", None),
        "code_interpreter": ("execute", None),
    }


def test_foundry_agent_version_fixture():
    # A saved "get agent version" response.
    agent = load_any(FIXTURES / "foundry_research_agent.json")
    assert agent.name == "research-agent"
    assert agent.instructions == "Answer research questions."
    assert agent.guardrail is True
    # file_search is a data source, not an action, and is not untrusted web content.
    assert agent.untrusted_knowledge is None
    tools = {t.name: (t.capability, t.requires_approval) for t in agent.tools}
    assert tools == {
        # No require_approval: Foundry's documented default is "always".
        "read_wiki_page": ("read", True),
        "update_wiki_page": ("write", True),
        # Function tools run in the caller's code, which decides on approval.
        "save_summary": ("write", None),
    }


def test_foundry_per_tool_approval(tmp_path):
    mcp = {
        "type": "mcp",
        "server_label": "crm",
        "server_url": "https://crm.example.com/mcp",
        "require_approval": {"always": {"tool_names": ["delete_contact"]}, "never": {"tool_names": ["list_contacts"]}},
        "allowed_tools": ["list_contacts", "delete_contact", "update_contact"],
    }
    version = {"object": "agent.version", "name": "crm", "definition": {"kind": "prompt", "model": "m", "tools": [mcp]}}
    agent = _parse(tmp_path, version)
    tools = {t.name: t.requires_approval for t in agent.tools}
    # A tool in neither list is not documented, so it stays None.
    assert tools == {"list_contacts": False, "delete_contact": True, "update_contact": None}


def test_foundry_mcp_without_named_tools_adds_no_tools(tmp_path):
    # The server's tools are not in the definition; we never connect to find them.
    mcp = {"type": "mcp", "server_label": "s", "server_url": "https://s.example.com/mcp", "require_approval": "never"}
    version = {"object": "agent.version", "name": "a", "definition": {"kind": "hosted", "tools": [mcp]}}
    agent = _parse(tmp_path, version)
    assert agent.tools == [] and len(agent.servers) == 1
    assert agent.instructions is None


def test_foundry_mcp_server_without_header_is_not_flagged():
    from discover_lite.checks import insecure_remote_server

    # Auth lives in the project connection, so a missing header says nothing.
    assert insecure_remote_server(load_any(FIXTURES / "foundry_support_agent.json")) == []


def test_bedrock_action_groups_match_on_agent_id_and_version(tmp_path):
    import json

    agent = {"agent": {"agentId": "AGENT00001", "agentName": "A", "agentVersion": "DRAFT"}}
    (tmp_path / "agent.json").write_text(json.dumps(agent))

    def group(name, agent_id, version):
        functions = {"functions": [{"name": name, "requireConfirmation": "DISABLED"}]}
        return {"agentActionGroup": {"actionGroupName": name, "agentId": agent_id, "agentVersion": version,
                                     "actionGroupState": "ENABLED", "functionSchema": functions}}

    (tmp_path / "mine.json").write_text(json.dumps(group("mine", "AGENT00001", "DRAFT")))
    # Another agent's group, and an older version of this agent's: both ignored.
    (tmp_path / "other.json").write_text(json.dumps(group("other", "AGENT00002", "DRAFT")))
    (tmp_path / "old.json").write_text(json.dumps(group("old", "AGENT00001", "1")))
    assert [t.name for t in load_any(tmp_path / "agent.json").tools] == ["mine"]
