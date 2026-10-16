"""Command-line entry point. Placeholder until milestone 0c adds scanning."""

from pathlib import Path

import typer

app = typer.Typer(help="Static analyser for AI agent configurations.")


@app.command()
def scan(folder: Path) -> None:
    """Scan FOLDER for agent config files."""
    typer.echo(f"Scanning {folder}: no connectors or checks yet.")
