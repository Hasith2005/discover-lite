"""Command-line entry point. Lists parsed agents until milestone 0c adds checks."""

from pathlib import Path

import typer

from discover_lite.connectors import load_any

app = typer.Typer(help="Static analyser for AI agent configurations.")


@app.command()
def scan(folder: Path) -> None:
    """Scan FOLDER for agent config files."""
    for path in sorted(folder.rglob("*.json")):
        agent = load_any(path)
        if agent is not None:
            typer.echo(f"{agent.name} ({agent.platform}) from {agent.source_file}")
