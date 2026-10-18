"""Command-line entry point.

    discover-lite scan <file or folder> [--json] [--report report.html]
    discover-lite report <file or folder> [-o report.html]
    discover-lite verify <file or folder>
    discover-lite coverage <file or folder>
    discover-lite fetch-github [--limit N]
    discover-lite fetch-registry [--limit N]
    discover-lite stats <folder>
    discover-lite review-secrets <folder>
"""

import json
from pathlib import Path

import typer

from discover_lite.checks import secret_in_config
from discover_lite import fetch_github, fetch_registry, stats
from discover_lite.connectors import load_agents
from discover_lite.coverage import cell, coverage
from discover_lite.mappings import load_mappings
from discover_lite.report import SEVERITY_ORDER, build_report, default_policies, scan_path
from discover_lite.verifier import load_policy, policy_path, verify

app = typer.Typer(help="Static analyser for AI agent configurations.")

# What a single file must be for a connector to read it.
SUPPORTED = (
    "a Copilot Studio agent, an AWS Bedrock agent, an MCP client config (Claude Desktop, "
    "Claude Code, Cursor, VS Code, Windsurf, Cline, Gemini CLI) or an MCP Registry page"
)

# A config file or a folder of them, for every command that scans.
TARGET = typer.Argument(..., exists=True, help="A config file, or a folder to scan for .json files.")


def _scan(target: Path):
    """Scan the target; a single file no connector recognises is an error, not a clean result."""
    results = scan_path(target)
    if target.is_file() and not results:
        typer.echo(f"{target}: not a config Discover Lite can read. Supported: {SUPPORTED}.", err=True)
        raise typer.Exit(1)
    return results


@app.command()
def scan(
    target: Path = TARGET,
    as_json: bool = typer.Option(False, "--json", help="Print results as JSON."),
    report_file: Path = typer.Option(None, "--report", help="Also write the HTML report to this file."),
) -> None:
    """Scan a config file, or every .json file under a folder, and report risky agent setups."""
    results = _scan(target)
    if report_file:
        report_file.write_text(build_report(target, default_policies(target)), encoding="utf-8")

    if as_json:
        mappings = load_mappings()
        output = [
            {
                # Only identifying fields: the full agent includes env and
                # header values, which may be secrets and must not be printed.
                "agent": r.agent.model_dump(include={"id", "name", "platform", "source_file"}),
                "score": r.score,
                "score_breakdown": {check: round(points, 2) for check, points in r.breakdown.items()},
                # Each finding plus the frameworks its check maps to.
                "findings": [{**f.model_dump(), "mapping": mappings[f.check_id]} for f in r.findings],
            }
            for r in results
        ]
        typer.echo(json.dumps(output, indent=2))
        return

    if report_file:
        typer.echo(f"Wrote {report_file}\n")

    for r in results:
        typer.echo(f"{r.agent.name}  ({r.agent.platform}, {r.agent.source_file})  risk {r.score:.0f}/100")
        if not r.findings:
            typer.echo("  No findings.")
        for f in r.findings:
            typer.echo(f"  [{f.severity.upper():6}] {f.check_id}: {f.evidence}")
        typer.echo("")

    all_findings = [f for r in results for f in r.findings]
    counts = {s: sum(f.severity == s for f in all_findings) for s in SEVERITY_ORDER}
    typer.echo(
        f"{len(results)} agent{'' if len(results) == 1 else 's'}, {len(all_findings)} findings "
        f"({counts['high']} high, {counts['medium']} medium, {counts['low']} low)"
    )
    # Show the limits of the capability heuristic, not just its results.
    tools = [t for r in results for t in r.agent.tools]
    unknown = sum(t.capability == "unknown" for t in tools)
    typer.echo(f"{unknown} of {len(tools)} tools could not be classified as read or write")


@app.command()
def report(
    target: Path = TARGET,
    output: Path = typer.Option(Path("report.html"), "-o", "--output", help="Where to write the report."),
    policies: Path = typer.Option(None, help="Policy folder (default: policies/ beside the file or in the folder)."),
    github: Path = typer.Option(Path("data/github-configs"), help="Downloaded GitHub configs, if any."),
    registry: Path = typer.Option(Path("data/registry"), help="Downloaded registry pages, if any."),
) -> None:
    """Write a self-contained HTML report for a config file or a folder."""
    _scan(target)  # Stop early on a file no connector can read.
    html = build_report(target, policies or default_policies(target), github, registry)
    output.write_text(html, encoding="utf-8")
    typer.echo(f"Wrote {output}")


@app.command("verify")
def verify_command(
    target: Path = TARGET,
    policies: Path = typer.Option(None, help="Policy folder (default: policies/ beside the file or in the folder)."),
) -> None:
    """Prove properties of each agent's tool policy with the Z3 solver."""
    policies = policies or default_policies(target)
    for r in _scan(target):
        path = policy_path(policies, r.agent)
        if not path.exists():
            continue
        typer.echo(f"{r.agent.name}  ({path})")
        for result in verify(r.agent, load_policy(path)):
            outcome = "PROVED  " if result.proved else "VIOLATED"
            typer.echo(f"  {outcome} {result.property}: {result.detail}")
        typer.echo("")


@app.command("coverage")
def coverage_command(
    target: Path = TARGET,
) -> None:
    """Show which security signals each platform's files actually contain."""
    table = coverage([r.agent for r in _scan(target)])
    platforms = list(table)
    typer.echo("| Signal | " + " | ".join(platforms) + " |")
    typer.echo("|---" * (len(platforms) + 1) + "|")
    for label in next(iter(table.values()), {}):
        typer.echo(f"| {label} | " + " | ".join(cell(*table[p][label]) for p in platforms) + " |")


@app.command("fetch-github")
def fetch_github_command(
    limit: int = typer.Option(300, help="Maximum number of new configs to download."),
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
    for label, count, share in stats.compute(agents, skipped) + stats.registry_rows(agents):
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
        for agent in load_agents(path):
            findings = secret_in_config(agent)
            if findings:
                typer.echo(f"{path}  ({agent.id})")
                for f in findings:
                    typer.echo(f"  {f.evidence}")
                hits += len(findings)
    typer.echo(f"Hits to review: {hits}")


@app.command("fetch-registry")
def fetch_registry_command(
    limit: int = typer.Option(
        0, min=0, help="How many entries to fetch, one per server version (0 = the whole registry)."
    ),
    out: Path = typer.Option(Path("data/registry"), help="Folder to save pages in."),
) -> None:
    """Download server definitions from the official MCP Registry."""
    entries = fetch_registry.fetch(out, limit, echo=typer.echo)
    typer.echo(f"Saved {entries} entries to {out}")
