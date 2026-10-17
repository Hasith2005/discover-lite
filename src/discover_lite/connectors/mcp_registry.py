"""Connector for pages saved from the official MCP Registry API.

Unlike the other connectors, one file (one page) holds many servers, so this
connector returns a list of Agents: one per registry entry. Each entry
describes how a server is published and installed, not how anyone has
configured it, and it does not list the server's tools.
"""

from pathlib import Path

from discover_lite.models import Agent, McpServer

# Key under "_meta" where the registry records its own information.
OFFICIAL_META = "io.modelcontextprotocol.registry/official"

# The command an MCP client would normally use to run each package type.
DEFAULT_RUNNER = {"npm": "npx", "pypi": "uvx"}


def matches(data: object) -> bool:
    """True if the parsed JSON looks like a registry API page."""
    return (
        isinstance(data, dict)
        and isinstance(data.get("servers"), list)
        and isinstance(data.get("metadata"), dict)
    )


def package_spec(registry_type: str, identifier: str, version: str | None) -> str:
    """The package argument a client would pass to the runner.

    npm "pkg" at "1.2.3" -> "pkg@1.2.3"; pypi -> "pkg==1.2.3". A missing
    version gives just "pkg". This lets the unpinned_package check judge
    registry entries with exactly the same rule as real client configs:
    "latest", ranges like "^1.2.0" and missing versions all count as unpinned.
    """
    if not version:
        return identifier
    separator = "==" if registry_type == "pypi" else "@"
    return f"{identifier}{separator}{version}"


def package_server(package: dict) -> McpServer:
    """One registry package as the local server a client would start."""
    registry_type = package.get("registryType")
    identifier = package["identifier"]
    return McpServer(
        name=identifier,
        # The publisher's hint wins (e.g. "bunx"); otherwise the usual runner.
        command=package.get("runtimeHint") or DEFAULT_RUNNER.get(registry_type, registry_type),
        args=[package_spec(registry_type, identifier, package.get("version"))],
        registry_type=registry_type,
        declared_secrets=[
            var["name"] for var in package.get("environmentVariables") or [] if var.get("isSecret")
        ],
    )


def parse_page(data: dict, path: Path) -> list[Agent]:
    agents = []
    for entry in data["servers"]:
        # The registry lists every published version. Keep only the latest,
        # so each server is counted once. A missing flag means the registry
        # does not say, so the entry is kept.
        if entry.get("_meta", {}).get(OFFICIAL_META, {}).get("isLatest") is False:
            continue
        server = entry["server"]
        servers = [package_server(p) for p in server.get("packages") or []]
        servers += [
            McpServer(name=f"{server['name']} (remote {i + 1})", url=remote["url"])
            for i, remote in enumerate(server.get("remotes") or [])
        ]
        agents.append(
            Agent(
                id=server["name"],
                name=server.get("title") or server["name"],
                platform="mcp_registry",
                source_file=str(path),
                servers=servers,
            )
        )
    return agents
