"""Command-line entry point.

    discover-lite scan <folder> [--json]
    discover-lite fetch-github [--limit N]
    discover-lite stats <folder>
    discover-lite review-secrets <folder>
"""

import json
from pathlib import Path

import typer

from discover_lite.checks import run_all, secret_in_config
from discover_lite import fetch_github, stats
from discover_lite.connectors import load_any

app = typer.Typer(help="Static analyser for AI agent configurations.")

# Used to list the most serious findings first.
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@app.command()
def scan(
    folder: Path = typer.Argument(..., exists=True, file_okay=False, help="Folder to scan."),
    as_json: bool = typer.Option(False, "--json", help="Print results as JSON."),
) -> None:
    """Scan every .json file under FOLDER and report risky agent setups."""
    results = []
    for path in sorted(folder.rglob("*.json")):
        agent = load_any(path)
        if agent is None:
            continue  # Not a config format we recognise.
        findings = sorted(run_all(agent), key=lambda f: SEVERITY_ORDER[f.severity])
        results.append((agent, findings))

    if as_json:
        output = [
            {
                # Only identifying fields: the full agent includes env and
                # header values, which may be secrets and must not be printed.
                "agent": agent.model_dump(include={"id", "name", "platform", "source_file"}),
                "findings": [f.model_dump() for f in findings],
            }
            for agent, findings in results
        ]
        typer.echo(json.dumps(output, indent=2))
        return

    for agent, findings in results:
        typer.echo(f"{agent.name}  ({agent.platform}, {agent.source_file})")
        if not findings:
            typer.echo("  No findings.")
        for f in findings:
            typer.echo(f"  [{f.severity.upper():6}] {f.check_id}: {f.evidence}")
        typer.echo("")

    all_findings = [f for _, findings in results for f in findings]
    counts = {s: sum(f.severity == s for f in all_findings) for s in SEVERITY_ORDER}
    typer.echo(
        f"{len(results)} agents, {len(all_findings)} findings "
        f"({counts['high']} high, {counts['medium']} medium, {counts['low']} low)"
    )
    # Show the limits of the capability heuristic, not just its results.
    tools = [t for agent, _ in results for t in agent.tools]
    unknown = sum(t.capability == "unknown" for t in tools)
    typer.echo(f"{unknown} of {len(tools)} tools could not be classified as read or write")


@app.command("fetch-github")
def fetch_github_command(
    limit: int = typer.Option(300, help="Maximum number of configs to download."),
    out: Path = typer.Option(Path("data/github-configs"), help="Folder to save them in."),
) -> None:
    """Download public MCP client configs from GitHub (needs `gh auth login`)."""
    saved = fetch_github.fetch(out, limit, echo=typer.echo)
    typer.echo(f"Saved {saved} configs to {out}")


@app.command("stats")
def stats_command(
    folder: Path = typer.Argument(..., exists=True, file_okay=False, help="Folder of configs."),
) -> None:
    """Print aggregate statistics (counts only, never values or names)."""
    agents, skipped = stats.collect(folder)
    typer.echo("| Measure | Count | Share |")
    typer.echo("|---|---|---|")
    for label, count, share in stats.compute(agents, skipped):
        typer.echo(f"| {label} | {count} | {share} |")
    typer.echo("")
    typer.echo("| Check | Severity | Findings | Configs affected | Share of configs |")
    typer.echo("|---|---|---|---|---|")
    for check, severity, n_findings, n_configs, share in stats.findings_by_check(agents):
        typer.echo(f"| {check} | {severity} | {n_findings} | {n_configs} | {share} |")
    typer.echo("")
    typer.echo("Most common commands for local servers:")
    for command, count in stats.top_commands(agents):
        typer.echo(f"  {command}: {count}")


@app.command("review-secrets")
def review_secrets_command(
    folder: Path = typer.Argument(..., exists=True, file_okay=False, help="Folder of configs."),
) -> None:
    """List each hard-coded secret hit for manual review (values redacted).

    Shows the local file to open, so a person can decide whether each hit is
    real, a test value or a false positive before any rate is quoted.
    """
    hits = 0
    for path in sorted(folder.rglob("*.json")):
        agent = load_any(path)
        if agent is None:
            continue
        findings = secret_in_config(agent)
        if findings:
            typer.echo(str(path))
            for f in findings:
                typer.echo(f"  {f.evidence}")
            hits += len(findings)
    typer.echo(f"Hits to review: {hits}")
