from pathlib import Path

from typer.testing import CliRunner

from discover_lite.cli import app

FIXTURES = Path(__file__).parent.parent / "fixtures"


def run(*args):
    return CliRunner().invoke(app, [str(a) for a in args])


def test_scan_one_file():
    result = run("scan", FIXTURES / "bedrock_travel_agent.json")
    assert result.exit_code == 0
    assert "Travel Booker" in result.output
    assert "1 agent, 3 findings" in result.output


def test_scan_one_file_writes_report(tmp_path):
    report = tmp_path / "report.html"
    result = run("scan", FIXTURES / "claude_desktop_config.json", "--report", report)
    assert result.exit_code == 0
    html = report.read_text()
    assert "secret_in_config" in html
    # The report shows the redacted secret, never the value itself.
    assert "FAKE_DB_PASSWORD_7f3a9c2e81b4" not in html


def test_report_and_verify_accept_one_file(tmp_path):
    # The policy is found in policies/ beside the file.
    result = run("verify", FIXTURES / "copilot_refunds_bot.json")
    assert result.exit_code == 0
    assert "VIOLATED" in result.output
    result = run("report", FIXTURES / "copilot_refunds_bot.json", "-o", tmp_path / "r.html")
    assert result.exit_code == 0
    assert "Refunds Bot" in (tmp_path / "r.html").read_text()


def test_unrecognised_file_is_an_error(tmp_path):
    # A shape no connector knows (here, made up) must not look like a clean result.
    unknown = tmp_path / "unknown_agent.json"
    unknown.write_text('{"name": "agent", "kind": "prompt"}')
    result = run("scan", unknown)
    assert result.exit_code == 1
    assert "not a config Discover Lite can read" in result.output


def test_verify_without_any_policy_fails(tmp_path):
    # No policy means nothing was checked, which must not read as a pass.
    config = tmp_path / "mcp.json"
    config.write_text('{"mcpServers": {"git": {"command": "uvx", "args": ["mcp-server-git==1.0.0"]}}}')
    result = run("verify", config)
    assert result.exit_code == 1
    assert "not verified" in result.output


def test_bedrock_action_group_alone_says_to_scan_its_agent():
    result = run("scan", FIXTURES / "bedrock_travel_agent.actiongroup_flights.json")
    assert result.exit_code == 1
    assert "read together with its agent" in result.output
