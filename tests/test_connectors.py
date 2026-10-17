from pathlib import Path

import pytest

from discover_lite.connectors import load_any
from discover_lite.connectors.copilot_export import infer_capability
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
                env={"DB_PASSWORD": "FAKE_DB_PASSWORD_FOR_TESTS"},
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
