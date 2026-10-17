"""Command-line entry point: discover-lite <folder> [--json]."""

import json
from pathlib import Path

import typer

from discover_lite.checks import run_all
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
