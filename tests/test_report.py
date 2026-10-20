import json
from pathlib import Path

from typer.testing import CliRunner

from discover_lite.cli import app
from discover_lite.report import build_report, scan_path, top_issues

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_report_has_every_section(tmp_path):
    html = build_report(FIXTURES, FIXTURES / "policies")
    for heading in [
        "Estate summary",
        "Agents by AIVSS score",
        "Agent details",
        "Policy verification",
        "What each platform tells us",
        "What this tool does not do",
    ]:
        assert heading in html
    assert "IssueRefund(amount=" in html
    # No real-world data was given, so that section is left out.
    assert "Real-world data" not in html


def test_report_never_contains_fixture_secret():
    assert "FAKE_DB_PASSWORD_7f3a9c2e81b4" not in build_report(FIXTURES, FIXTURES / "policies")


def test_report_escapes_html_from_configs(tmp_path):
    # A config is untrusted input: a server name with HTML in it must be
    # shown as text, not become part of the page.
    config = {"mcpServers": {"<script>alert(1)</script>": {"url": "http://evil.example.com/mcp"}}}
    (tmp_path / "evil.json").write_text(json.dumps(config))
    html = build_report(tmp_path)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_top_issues_are_plain_sentences():
    issues = top_issues(scan_path(FIXTURES))
    assert len(issues) == 3
    # no_human_in_loop affects the most agents (HR Helper, Refunds Bot, Travel Booker).
    assert issues[0] == "4 of 14 agents have a tool that changes data with no approval."


def test_report_command_writes_file(tmp_path):
    out = tmp_path / "report.html"
    result = CliRunner().invoke(
        app, ["report", str(FIXTURES), "-o", str(out), "--github", str(tmp_path / "none"), "--registry", str(tmp_path / "none")]
    )
    assert result.exit_code == 0
    assert out.read_text().startswith("<!doctype html>")


def test_verify_command():
    result = CliRunner().invoke(app, ["verify", str(FIXTURES)])
    assert result.exit_code == 0
    assert "VIOLATED Every allowed write needs approval" in result.output
    assert "PROVED   Every tool is covered" in result.output


def test_coverage_command():
    result = CliRunner().invoke(app, ["coverage", str(FIXTURES)])
    assert result.exit_code == 0
    assert "| Guardrail setting | 2/2 | 0/7 | 1/2 | 0/3 |" in result.output


def test_report_says_what_is_published_and_what_is_judgement():
    from discover_lite import checks
    from discover_lite.report import build_report

    page = build_report(FIXTURES)
    assert "Where each part comes from" in page
    assert "OWASP AIVSS v0.8" in page and "gitleaks v8.30.1" in page
    # Thresholds come from the code, so the report cannot drift from it.
    assert f"Instructions under {checks.MIN_INSTRUCTION_WORDS} words" in page
    assert f"similarity {checks.TOPIC_OVERLAP_THRESHOLD} or more" in page
