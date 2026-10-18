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
from discover_lite.connectors import load_agents
from discover_lite.models import Agent, McpServer


def percent(part: int, whole: int) -> str:
    """"3 of 12" as "25.0%", or "-" when there is nothing to divide by.

    A share that is above zero but rounds to 0.0% is shown as "<0.1%", so a
    small number is not mistaken for none.
    """
    if not whole:
        return "-"
    share = 100 * part / whole
    if 0 < share < 0.05:
        return "<0.1%"
    return f"{share:.1f}%"


def _single(agent: Agent, server: McpServer) -> Agent:
    """A copy of the agent holding just one server, so a check can be asked
    about that server alone. This reuses the checks exactly as written."""
    return agent.model_copy(update={"servers": [server]})


def _has_high(findings: list) -> bool:
    return any(f.severity == "high" for f in findings)


def collect(folder: Path) -> tuple[list[Agent], int]:
    """Parse every .json file; return the agents and the number of files skipped."""
    agents, skipped = [], 0
    for path in sorted(folder.rglob("*.json")):
        found = load_agents(path)
        if not found:
            skipped += 1
        agents.extend(found)
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
    # Only high findings count as a hard-coded secret. Low ones are text a
    # person typed (a password or a placeholder) and are counted separately.
    secret_servers = sum(_has_high(secret_in_config(_single(a, s))) for a, s in servers)
    secret_configs = sum(_has_high(secret_in_config(a)) for a in agents)
    typed_configs = sum(
        not _has_high(found) and bool(found) for found in (secret_in_config(a) for a in agents)
    )
    any_finding = sum(bool(run_all(a)) for a in agents)

    return [
        ("Files with no current agents (unrecognised, invalid, or only old registry versions)", skipped, ""),
        ("Configs parsed", len(agents), ""),
        ("Configs with at least one finding", any_finding, percent(any_finding, len(agents))),
        ("Configs with a hard-coded secret", secret_configs, percent(secret_configs, len(agents))),
        ("Configs with only typed values under secret names (password or placeholder)", typed_configs, percent(typed_configs, len(agents))),
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


def findings_by_check(agents: list[Agent]) -> list[tuple[str, str, int, int, str]]:
    """Rows of (check id, severity, findings, configs affected, share of configs).

    A check can report more than one severity (insecure_remote_server has a
    high and a low case), so each (check, severity) pair gets its own row.
    """
    findings = Counter()
    configs = Counter()
    for agent in agents:
        pairs = [(f.check_id, f.severity) for f in run_all(agent)]
        findings.update(pairs)
        configs.update(set(pairs))  # Count each config once per row.
    order = {"high": 0, "medium": 1, "low": 2}
    rows = sorted(findings, key=lambda pair: (order[pair[1]], -configs[pair]))
    return [
        (check, severity, findings[(check, severity)], configs[(check, severity)],
         percent(configs[(check, severity)], len(agents)))
        for check, severity in rows
    ]


def registry_rows(agents: list[Agent]) -> list[tuple[str, int, str]]:
    """Extra rows for MCP Registry entries; empty if there are none."""
    entries = [a for a in agents if a.platform == "mcp_registry"]
    if not entries:
        return []
    n = len(entries)
    with_package = [a for a in entries if any(s.command is not None for s in a.servers)]
    with_remote = [a for a in entries if any(s.url is not None for s in a.servers)]
    # Compare by id: checking "a in with_remote" would compare whole models
    # against every entry in the list, which is very slow on 45,000 servers.
    remote_ids = {a.id for a in with_remote}
    both = [a for a in with_package if a.id in remote_ids]
    unpinned = [a for a in entries if unpinned_package(a)]
    plain_http = [
        a for a in entries if any(f.severity == "high" for f in insecure_remote_server(a))
    ]
    declares_secret = [a for a in entries if any(s.declared_secrets for s in a.servers)]
    packages = [s for a in entries for s in a.servers if s.command is not None]

    rows = [
        ("Registry servers (latest version of each)", n, ""),
        ("Servers with a package (stdio)", len(with_package), percent(len(with_package), n)),
        ("Servers with a remote endpoint", len(with_remote), percent(len(with_remote), n)),
        ("Servers with both", len(both), percent(len(both), n)),
        ("Servers with an unpinned package", len(unpinned), percent(len(unpinned), n)),
        ("Servers with a plain-HTTP remote (non-local)", len(plain_http), percent(len(plain_http), n)),
        ("Servers declaring a secret environment variable", len(declares_secret), percent(len(declares_secret), n)),
        ("Packages", len(packages), ""),
    ]
    for registry_type, count in Counter(s.registry_type for s in packages).most_common():
        rows.append((f"Packages from {registry_type}", count, percent(count, len(packages))))
    return rows
