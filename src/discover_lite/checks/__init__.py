"""Posture checks: pure functions that take an Agent and return Findings.

Each check's id is its function name. Checks are deterministic rules, and they
only fire on explicit values: a field that is None ("the platform does not
say") never counts as a failure.
"""

import re
from pathlib import Path
from urllib.parse import urlparse

from discover_lite.models import Agent, Finding

# A value like "${API_KEY}" is a reference to an environment variable, which is
# the safe way to pass a secret, so it is not a finding.
ENV_REFERENCE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}")

# Parts of a name that suggest the value is a secret. Matched as substrings of
# the lowercased name, so "DB_PASSWORD" and "Authorization" both match.
SECRET_NAME_WORDS = ("key", "token", "secret", "password", "auth", "credential")

# Well-known key formats: OpenAI-style, GitHub personal access token, AWS access key id.
KNOWN_KEY_FORMATS = [
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
]

# Commands that download and run a package in one step.
PACKAGE_RUNNERS = {"npx", "uvx", "bunx", "pnpx"}

# Exact versions: "pkg@1.2.3" or "@scope/pkg@1.2.3" (npm style, optional
# pre-release like "-beta.1"), or "pkg==1.2.3" (Python style).
NPM_PINNED = re.compile(r"(@[^/@\s]+/)?[^@\s]+@\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?")
PYTHON_PINNED = re.compile(r"[^=\s]+==\d+(\.\d+)*")

# Hosts on the same machine, where plain HTTP never crosses the network.
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

MIN_INSTRUCTION_WORDS = 10


def redact(value: str) -> str:
    """Hide a secret: keep the first three characters, e.g. "FAKE_TOKEN" -> "FAK****"."""
    return value[:3] + "****"


def _looks_like_secret(name: str, value: str) -> bool:
    if not value or ENV_REFERENCE.fullmatch(value):
        return False
    if any(word in name.lower() for word in SECRET_NAME_WORDS):
        return True
    return any(pattern.search(value) for pattern in KNOWN_KEY_FORMATS)


def secret_in_config(agent: Agent) -> list[Finding]:
    """A secret written directly into an MCP server's env, headers or args."""
    findings = []
    for server in agent.servers:
        named_values = [("env", k, v) for k, v in server.env.items()]
        named_values += [("header", k, v) for k, v in server.headers.items()]
        for where, name, raw in named_values:
            # "Bearer abc" -> "abc", so we judge the token itself.
            value = raw.removeprefix("Bearer ")
            if _looks_like_secret(name, value):
                findings.append(
                    Finding(
                        check_id="secret_in_config",
                        agent_id=agent.id,
                        severity="high",
                        evidence=f"Server '{server.name}' {where} {name} = {redact(value)}",
                        recommendation="Move the value into an environment variable and reference it as ${VAR}.",
                    )
                )
        # Arguments have no names, so only known key formats count here.
        for arg in server.args:
            for pattern in KNOWN_KEY_FORMATS:
                match = pattern.search(arg)
                if match:
                    findings.append(
                        Finding(
                            check_id="secret_in_config",
                            agent_id=agent.id,
                            severity="high",
                            evidence=f"Server '{server.name}' argument contains a key: {redact(match.group())}",
                            recommendation="Pass the key through an environment variable, not a command-line argument.",
                        )
                    )
    return findings


def _is_pinned(package: str) -> bool:
    return bool(NPM_PINNED.fullmatch(package) or PYTHON_PINNED.fullmatch(package))


def unpinned_package(agent: Agent) -> list[Finding]:
    """A package runner (npx, uvx, ...) fetching a package with no exact version."""
    findings = []
    for server in agent.servers:
        # Path(...).name turns "/usr/bin/npx" into "npx".
        if server.command is None or Path(server.command).name not in PACKAGE_RUNNERS:
            continue
        # The package is the first argument that is not a flag like "-y".
        # Limitation: a flag that takes a value (e.g. "--from pkg") is not handled.
        package = next((a for a in server.args if not a.startswith("-")), None)
        if package is None:
            continue
        if not _is_pinned(package):
            findings.append(
                Finding(
                    check_id="unpinned_package",
                    agent_id=agent.id,
                    severity="medium",
                    evidence=f"Server '{server.name}' runs '{server.command} {package}' with no exact version",
                    recommendation="Pin an exact version, e.g. pkg@1.2.3, so a new release cannot change what runs.",
                )
            )
    return findings


def insecure_remote_server(agent: Agent) -> list[Finding]:
    """A remote MCP server reached over plain HTTP, or with no Authorization header."""
    findings = []
    for server in agent.servers:
        if server.url is None:
            continue
        url = urlparse(server.url)
        # Servers on this machine are skipped: traffic never leaves it.
        if url.hostname in LOCAL_HOSTS:
            continue
        if url.scheme == "http":
            findings.append(
                Finding(
                    check_id="insecure_remote_server",
                    agent_id=agent.id,
                    severity="high",
                    evidence=f"Server '{server.name}' uses plain HTTP: {server.url}",
                    recommendation="Use https:// so traffic and credentials are encrypted.",
                )
            )
        # Header names are case-insensitive in HTTP.
        if not any(name.lower() == "authorization" for name in server.headers):
            findings.append(
                Finding(
                    check_id="insecure_remote_server",
                    agent_id=agent.id,
                    severity="low",
                    evidence=f"Server '{server.name}' sends no Authorization header (it may use OAuth instead)",
                    recommendation="Confirm the server requires authentication.",
                )
            )
    return findings


def missing_scope(agent: Agent) -> list[Finding]:
    """Instructions that are empty or too short to limit what the agent does."""
    # MCP client configs have no instructions field at all, and None means the
    # platform does not say, so neither case counts as a failure.
    if agent.platform == "mcp_client" or agent.instructions is None:
        return []
    word_count = len(agent.instructions.split())
    if word_count >= MIN_INSTRUCTION_WORDS:
        return []
    return [
        Finding(
            check_id="missing_scope",
            agent_id=agent.id,
            severity="medium",
            evidence=f"Instructions are {word_count} words long (fewer than {MIN_INSTRUCTION_WORDS})",
            recommendation="Write instructions that state the agent's purpose, limits and what it must refuse.",
        )
    ]


def no_human_in_loop(agent: Agent) -> list[Finding]:
    """A write or execute tool that explicitly runs without approval."""
    return [
        Finding(
            check_id="no_human_in_loop",
            agent_id=agent.id,
            severity="high",
            evidence=f"Tool '{tool.name}' ({tool.capability}) runs without approval",
            recommendation="Require user consent or approval before this tool runs.",
        )
        for tool in agent.tools
        # "is False", not "not ...": None means unknown and must not fire.
        if tool.capability in ("write", "execute") and tool.requires_approval is False
    ]


def open_access(agent: Agent) -> list[Finding]:
    """An agent anyone can use: no authentication, or shared with the whole organisation."""
    findings = []
    # The string "None" is the platform's setting for no authentication.
    # Python None would mean the setting is missing, which does not fire.
    if agent.authentication == "None":
        findings.append(
            Finding(
                check_id="open_access",
                agent_id=agent.id,
                severity="high",
                evidence='Authentication is set to "None"',
                recommendation="Require sign-in, e.g. Microsoft Entra.",
            )
        )
    if agent.shared_org_wide is True:
        findings.append(
            Finding(
                check_id="open_access",
                agent_id=agent.id,
                severity="medium",
                evidence="Shared with the entire organisation",
                recommendation="Share only with the groups that need this agent.",
            )
        )
    return findings


ALL_CHECKS = [
    secret_in_config,
    unpinned_package,
    insecure_remote_server,
    missing_scope,
    no_human_in_loop,
    open_access,
]


def run_all(agent: Agent) -> list[Finding]:
    """Run every registered check on one agent."""
    return [finding for check in ALL_CHECKS for finding in check(agent)]
