"""Aggregate statistics over a folder of configs.

Only counts and percentages come out of here: no file names, repository
names or values, so the output is safe to share.
"""

from collections import Counter
from pathlib import Path

from discover_lite.checks import (
    PACKAGE_RUNNERS,
    _package_argument,
    insecure_remote_server,
    run_all,
    secret_in_config,
    unpinned_package,
)
from discover_lite.connectors import load_any
from discover_lite.models import Agent, McpServer


def percent(part: int, whole: int) -> str:
    """"3 of 12" as "25.0%", or "-" when there is nothing to divide by."""
    return f"{100 * part / whole:.1f}%" if whole else "-"


def _single(agent: Agent, server: McpServer) -> Agent:
    """A copy of the agent holding just one server, so a check can be asked
    about that server alone. This reuses the checks exactly as written."""
    return agent.model_copy(update={"servers": [server]})


def collect(folder: Path) -> tuple[list[Agent], int]:
    """Parse every .json file; return the agents and the number of files skipped."""
    agents, skipped = [], 0
    for path in sorted(folder.rglob("*.json")):
        agent = load_any(path)
        if agent is None:
            skipped += 1
        else:
            agents.append(agent)
    return agents, skipped


def compute(agents: list[Agent], skipped: int) -> list[tuple[str, int, str]]:
    """Rows of (label, count, percentage of the relevant total)."""
    servers = [(a, s) for a in agents for s in a.servers]
    local = [(a, s) for a, s in servers if s.command is not None]
    remote = [(a, s) for a, s in servers if s.url is not None]
    runner = [(a, s) for a, s in local if Path(s.command).name in PACKAGE_RUNNERS]

    unpinned = sum(bool(unpinned_package(_single(a, s))) for a, s in runner)
    # Asking for "@latest" by name: a choice to always run the newest release.
    latest = sum((_package_argument(s.args) or "").endswith("@latest") for a, s in runner)
    plain_http = sum(
        any(f.severity == "high" for f in insecure_remote_server(_single(a, s))) for a, s in remote
    )
    no_auth = sum(
        any(f.severity == "low" for f in insecure_remote_server(_single(a, s))) for a, s in remote
    )
    secret_servers = sum(bool(secret_in_config(_single(a, s))) for a, s in servers)
    secret_configs = sum(bool(secret_in_config(a)) for a in agents)
    any_finding = sum(bool(run_all(a)) for a in agents)

    n_files = len(agents) + skipped
    return [
        ("Files read", n_files, ""),
        ("Files not recognised or not valid JSON", skipped, percent(skipped, n_files)),
        ("Configs parsed", len(agents), percent(len(agents), n_files)),
        ("Configs with at least one finding", any_finding, percent(any_finding, len(agents))),
        ("Configs with a hard-coded secret", secret_configs, percent(secret_configs, len(agents))),
        ("Servers", len(servers), ""),
        ("Local servers (command)", len(local), percent(len(local), len(servers))),
        ("Remote servers (url)", len(remote), percent(len(remote), len(servers))),
        ("Servers with a hard-coded secret", secret_servers, percent(secret_servers, len(servers))),
        ("Local servers started by a package runner", len(runner), percent(len(runner), len(local))),
        ("Package-runner servers with no exact version", unpinned, percent(unpinned, len(runner))),
        ("Package-runner servers asking for @latest", latest, percent(latest, len(runner))),
        ("Remote servers on plain HTTP (non-local)", plain_http, percent(plain_http, len(remote))),
        ("Remote servers with no Authorization header", no_auth, percent(no_auth, len(remote))),
    ]


def top_commands(agents: list[Agent], n: int = 8) -> list[tuple[str, int]]:
    """The most common commands used to start local servers."""
    commands = Counter(
        Path(s.command).name for a in agents for s in a.servers if s.command is not None
    )
    return commands.most_common(n)
