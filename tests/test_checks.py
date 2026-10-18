import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from discover_lite.checks import (
    ALL_CHECKS,
    broad_filesystem_access,
    insecure_remote_server,
    missing_scope,
    no_guardrail,
    no_human_in_loop,
    open_access,
    prompt_injection_exposure,
    redact,
    run_all,
    secret_in_config,
    topic_overlap,
    unclassified_tool,
    unpinned_package,
)
from discover_lite.cli import app
from discover_lite.connectors import load_any
from discover_lite.models import Agent, McpServer, Tool

FIXTURES = Path(__file__).parent.parent / "fixtures"

# Synthetic values in well-known key formats: the right shape and random
# enough for gitleaks' rules, but marked FAKE so nobody mistakes them.
FAKE_OPENAI_KEY = "sk-FAKE0123456789abcdef" + "T3BlbkFJ" + "FAKE0123456789abcdef"
FAKE_GITHUB_TOKEN = "ghp_FAKE" + "0123456789abcdefghijklmnopqrstuv"
FAKE_AWS_KEY = "AKIA" + "FAKE234567QRSTUV"
FAKE_SLACK_TOKEN = "xoxb-1234567890-0987654321-FAKEfake"
# A JSON Web Token: header, claims {"sub": "FAKE"} and a made-up signature.
FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJGQUtFIn0.FAKEsignature0123456789abcdef"


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
        # Generated-looking values under secret-sounding names.
        {"env": {"DB_PASSWORD": "FAKE_DB_PASSWORD_7f3a9c2e81b4"}},
        {"env": {"API_KEY": "FAKE-9f8e7d6c5b4a3210"}},
        {"headers": {"Authorization": "Bearer FAKE-token-4b8d2f6a9c1e"}},
        # Harmless name, but the value is a known vendor format (gitleaks).
        {"env": {"OPENAI": FAKE_OPENAI_KEY}},
        {"env": {"SLACK": FAKE_SLACK_TOKEN}},
        {"args": ["--token", FAKE_GITHUB_TOKEN]},
        {"args": [f"--aws={FAKE_AWS_KEY}"]},
        # A token passed as a header argument to a gateway (seen in real data).
        {"args": ["--header", "authorization:Bearer " + FAKE_JWT]},
    ],
)
def test_secret_in_config_fires_high(fields):
    findings = secret_in_config(mcp_agent(**fields))
    assert len(findings) == 1
    assert findings[0].severity == "high"


@pytest.mark.parametrize(
    "value",
    [
        # Text a person typed, from real public configs (with names changed):
        # placeholders in several languages, sample passwords, demo tokens.
        "FAKE_PASSWORD_FOR_TESTS",
        "seu_token_aqui",
        "{secret}",
        "\u60a8\u7684tushare\u4ee4\u724c",  # Chinese for "your tushare token".
        "MyPassword123",
        "test-token-123",
        "acme-demo-readonly-token-public-not-reuse",
    ],
)
def test_secret_in_config_typed_value_is_low(value):
    [finding] = secret_in_config(mcp_agent(env={"API_TOKEN": value}))
    assert finding.severity == "low"
    assert "looks typed" in finding.evidence


def test_secret_in_config_names_the_gitleaks_rule():
    [finding] = secret_in_config(mcp_agent(env={"OPENAI": FAKE_OPENAI_KEY}))
    assert "gitleaks rule 'openai-api-key'" in finding.evidence


@pytest.mark.parametrize(
    "fields",
    [
        {"env": {"API_KEY": "${API_KEY}"}},
        {"headers": {"Authorization": "Bearer ${TICKETS_TOKEN}"}},
        {"env": {"LOG_LEVEL": "debug"}},
        {"env": {"API_KEY": ""}},
        # "sk-" inside a word is not a key (real registry package names).
        {"args": ["@ellul-estate/breakerdesk-com-breakerdesk-electrician-tools-mcp"]},
        {"args": ["https://example.com/v0.3.0/task-graph-mcp-x86_64-unknown-linux-gnu.mcpb"]},
        # A plain word in args is not a key, even after "--token".
        {"args": ["-y", "some-package", "--token", "short"]},
        # A package pinned to a git commit: 40 hex characters, but not a key.
        {"args": ["--from", "git+https://github.com/acme/tool@" + "0123456789abcdef" * 2 + "01234567", "tool"]},
        # A random-looking value under a harmless name is not a secret.
        {"env": {"BUILD_ID": "9f8e7d6c5b4a3210abcdef"}},
        # A Google key from public docs, which gitleaks lists as an example.
        {"env": {"GOOGLE": "AIzaSyabcdefghijklmnopqrstuvwxyz1234567"}},
        # Other reference styles.
        {"env": {"API_KEY": "${env:API_KEY}"}},
        {"env": {"API_KEY": "${input:api_key}"}},
        {"env": {"API_KEY": "$API_KEY"}},
        {"env": {"API_KEY": "%API_KEY%"}},
        {"env": {"API_KEY": "{{api_key}}"}},
        # Placeholders copied from READMEs.
        {"env": {"API_KEY": "YOUR_API_KEY_HERE"}},
        {"env": {"GITHUB_TOKEN": "<your-token>"}},
        {"env": {"SECRET": "xxxxxxxxxxxx"}},
        {"env": {"OPENAI_API_KEY": "sk-..."}},
        {"env": {"OPENAI_API_KEY": "sk-your-openai-api-key-goes-in"}},
        {"headers": {"Authorization": "Bearer <token>"}},
        {"args": ["--key", "sk-replace-with-your-real-key"]},
        # Settings that sit under secret-sounding names.
        {"env": {"AUTH_ENABLED": "true"}},
        {"env": {"TOKEN_LIMIT": "100000000"}},
        {"env": {"AUTH_URL": "https://auth.example.com/login"}},
        {"env": {"KEY_FILE": "/home/demo/.ssh/id_ed25519"}},
        {"env": {"KEY_FILE": "C:\\Users\\demo\\key.pem"}},
        # A reference followed by a path.
        {"env": {"OAUTH_SECRETS_FILE": "${HOME}/keys/client.json"}},
        # Names that describe a secret rather than hold one.
        {"env": {"AUTH_METHOD": "api_key_header"}},
        {"env": {"TOKEN_PROVIDER": "azure_cli_login"}},
        # Default words, not chosen secrets.
        {"env": {"NEO4J_PASSWORD": "password"}},
    ],
)
def test_secret_in_config_does_not_fire(fields):
    assert secret_in_config(mcp_agent(**fields)) == []


@pytest.mark.parametrize(
    "fields, secret",
    [
        ({"env": {"DB_PASSWORD": "FAKE_DB_PASSWORD_7f3a9c2e81b4"}}, "FAKE_DB_PASSWORD_7f3a9c2e81b4"),
        ({"env": {"DB_PASSWORD": "FAKE_PASSWORD_FOR_TESTS"}}, "FAKE_PASSWORD_FOR_TESTS"),
        ({"headers": {"Authorization": "Bearer FAKE-token-4b8d2f6a9c1e"}}, "FAKE-token-4b8d2f6a9c1e"),
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
        ("npx", ["-p", "some-package", "some-command"]),
        ("uvx", ["--from", "git+https://example.com/repo", "server"]),
        ("uvx", ["--python", "3.12", "mcp-server-git"]),
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
        # Python pre-release, post-release and dev versions are still exact.
        ("uvx", ["some-server==0.1.0a4"]),
        ("uvx", ["some-server==0.1.0rc2"]),
        ("uvx", ["some-server==1.0.post1"]),
        ("uvx", ["some-server==3.0.0.dev1"]),
        ("uvx", ["some-server==2026.10.12.1"]),
        # The package comes from the flag, not the command after it.
        ("npx", ["--package=some-package@1.2.3", "some-command"]),
        ("npx", ["-p", "some-package@1.2.3", "some-command"]),
        ("uvx", ["--from", "mcp-server-git==1.2.3", "mcp-server-git"]),
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


# --- prompt_injection_exposure ----------------------------------------------


def test_prompt_injection_exposure_fires_for_hr_helper():
    agent = load_any(FIXTURES / "copilot_hr_helper.json")
    [finding] = prompt_injection_exposure(agent)
    assert finding.severity == "high"
    assert "SendEmailV2" in finding.evidence
    # EscalateCase is "unknown", so it is not named as an action tool.
    assert "EscalateCase" not in finding.evidence


@pytest.mark.parametrize("capability", ["write", "execute"])
def test_prompt_injection_exposure_fires(capability):
    tool = Tool(name="DoThing", capability=capability)
    findings = prompt_injection_exposure(copilot_agent(untrusted_knowledge=True, tools=[tool]))
    assert [f.severity for f in findings] == ["high"]


@pytest.mark.parametrize(
    "fields",
    [
        # Only read-only tools: nothing to act with.
        {"untrusted_knowledge": True, "tools": [Tool(name="GetFile", capability="read")]},
        # An unclassified tool is unclassified_tool's job, not this check's.
        {"untrusted_knowledge": True, "tools": [Tool(name="Mystery", capability="unknown")]},
        # Platform does not say whether it reads untrusted content.
        {"untrusted_knowledge": None, "tools": [write_tool(requires_approval=False)]},
        {"untrusted_knowledge": False, "tools": [write_tool(requires_approval=False)]},
    ],
)
def test_prompt_injection_exposure_does_not_fire(fields):
    assert prompt_injection_exposure(copilot_agent(**fields)) == []


# --- topic_overlap ----------------------------------------------------------


def test_topic_overlap_fires_for_hr_helper():
    agent = load_any(FIXTURES / "copilot_hr_helper.json")
    [finding] = topic_overlap(agent)
    assert finding.severity == "medium"
    assert "'reset_password' and 'unlock_account'" in finding.evidence
    assert "similarity 0.17" in finding.evidence
    # The word that drove the score is named; stop words like "my" are not.
    assert finding.evidence.endswith("shared words: password")


def test_topic_overlap_lists_shared_words_strongest_first():
    topics = {
        "track_order": ["track my order", "where is my order", "order status"],
        "cancel_order": ["cancel my order", "stop my order", "I want to cancel an order"],
    }
    [finding] = topic_overlap(copilot_agent(topics=topics))
    assert finding.evidence.endswith("shared words: order")


@pytest.mark.parametrize(
    "topics",
    [
        # Clearly different topics.
        {
            "book_leave": ["book annual leave", "request time off"],
            "reset_password": ["reset my password", "I forgot my password"],
        },
        # Only stop words in common ("my"), which must not count.
        {
            "payslip": ["show my payslip", "when is payday"],
            "laptop": ["my laptop is broken", "request a new laptop"],
        },
        # Fewer than two topics: nothing to compare.
        {"reset_password": ["reset my password"]},
        {},
        # No usable words at all.
        {"a": [], "b": ["the"]},
    ],
)
def test_topic_overlap_does_not_fire(topics):
    assert topic_overlap(copilot_agent(topics=topics)) == []


# --- broad_filesystem_access ------------------------------------------------

FILESYSTEM = "@modelcontextprotocol/server-filesystem@0.6.2"


@pytest.mark.parametrize(
    "path", ["/", "~", "${userHome}", "$HOME", "/home/alice", "/Users/alice/", "C:\\", "C:/Users/alice"]
)
def test_broad_filesystem_access_fires(path):
    findings = broad_filesystem_access(mcp_agent(command="npx", args=["-y", FILESYSTEM, path]))
    assert [f.severity for f in findings] == ["medium"]
    assert path in findings[0].evidence


@pytest.mark.parametrize(
    "fields",
    [
        # A project folder, not a whole home.
        {"command": "npx", "args": ["-y", FILESYSTEM, "/home/alice/projects/app"]},
        # Another server whose argument happens to be "/": not a filesystem grant.
        {"command": "npx", "args": ["-y", "some-web-server@1.0.0", "/"]},
        {"url": "https://files.example.com/mcp"},
    ],
)
def test_broad_filesystem_access_does_not_fire(fields):
    assert broad_filesystem_access(mcp_agent(**fields)) == []


# --- no_guardrail -------------------------------------------------------------


def test_no_guardrail_fires_on_explicit_false():
    assert [f.severity for f in no_guardrail(copilot_agent(guardrail=False))] == ["medium"]


@pytest.mark.parametrize("guardrail", [True, None])
def test_no_guardrail_does_not_fire(guardrail):
    assert no_guardrail(copilot_agent(guardrail=guardrail)) == []


# --- end to end -------------------------------------------------------------


def test_fixtures_trigger_every_check():
    fired = set()
    for path in FIXTURES.rglob("*.json"):
        fired |= {f.check_id for f in run_all(load_any(path))}
    assert fired == {check.__name__ for check in ALL_CHECKS}


def test_estate_has_clean_agents():
    # At least one well-set-up agent must pass every check.
    clean = {load_any(p).name for p in FIXTURES.rglob("*.json") if not run_all(load_any(p))}
    assert {"IT Helpdesk", "Claims Helper"} <= clean


@pytest.mark.parametrize("extra_args", [[], ["--json"]])
def test_cli_never_prints_fixture_secret(extra_args):
    result = CliRunner().invoke(app, ["scan", str(FIXTURES), *extra_args])
    assert result.exit_code == 0
    assert "FAKE_DB_PASSWORD_7f3a9c2e81b4" not in result.output


def test_cli_json_output():
    result = CliRunner().invoke(app, ["scan", str(FIXTURES), "--json"])
    data = json.loads(result.output)
    by_name = {entry["agent"]["name"]: entry for entry in data}
    assert len(data) == 12
    assert {"HR Helper", "Travel Booker", "web-app/.mcp.json"} <= set(by_name)
    hr = by_name["HR Helper"]
    # The agent takes its highest finding's AIVSS range, and every security
    # finding carries the inputs behind its score.
    assert (hr["aivss"]["low"], hr["aivss"]["score"]) == (9.1, 10.0)
    assert len(hr["aivss"]["factors"]) == 10
    scored = [f for f in hr["findings"] if "aivss" in f]
    assert max(f["aivss"] for f in scored) == hr["aivss"]["score"]
    assert all(f["cvss_v4"].startswith("CVSS:4.0/") for f in scored)
    # Quality findings are not vulnerabilities, so they get no score.
    assert all("aivss" not in f for f in hr["findings"] if f["check_id"] == "topic_overlap")


def test_stats_on_fixtures():
    from discover_lite import stats

    agents, skipped = stats.collect(FIXTURES)
    rows = {label: (count, share) for label, count, share in stats.compute(agents, skipped)}
    assert rows["Configs parsed"] == (12, "")
    # Three MCP client files hold 9 servers between them.
    assert rows["Servers"][0] == 9
    # postgres and git are unpinned; the other four runners are pinned.
    assert rows["Package-runner servers with no exact version"] == (2, "33.3%")
    # legacy-wiki is plain HTTP; the two other remotes use HTTPS.
    assert rows["Remote servers on plain HTTP (non-local)"] == (1, "33.3%")
    assert rows["Servers with a hard-coded secret"] == (1, "11.1%")
    # The fixture password looks generated, so it is high, not a typed value.
    assert rows["Configs with only typed values under secret names (password or placeholder)"] == (0, "0.0%")


def test_review_secrets_lists_file_but_not_secret():
    result = CliRunner().invoke(app, ["review-secrets", str(FIXTURES)])
    assert result.exit_code == 0
    assert "claude_desktop_config.json" in result.output
    assert "FAK****" in result.output
    assert "FAKE_DB_PASSWORD_7f3a9c2e81b4" not in result.output


def test_findings_by_check_on_fixtures():
    from discover_lite import stats

    agents, _ = stats.collect(FIXTURES)
    rows = {(check, sev): (n, configs) for check, sev, n, configs, _ in stats.findings_by_check(agents)}
    # open_access has two severities: HR Helper has both, Sales Assistant
    # only the medium one (shared with the whole organisation).
    assert rows[("open_access", "high")] == (1, 1)
    assert rows[("open_access", "medium")] == (2, 2)
    assert rows[("secret_in_config", "high")] == (1, 1)


@pytest.mark.parametrize(
    "part, whole, expected",
    [(3, 12, "25.0%"), (0, 12, "0.0%"), (1, 45372, "<0.1%"), (1, 0, "-")],
)
def test_percent(part, whole, expected):
    from discover_lite.stats import percent

    assert percent(part, whole) == expected
