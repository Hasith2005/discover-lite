"""Connector for the `mcpServers` config format.

Claude Desktop (claude_desktop_config.json) and Claude Code (.mcp.json) share
this format. The whole file describes one client, so it becomes one Agent.
This connector only reads JSON; it never starts or connects to a server.
"""

from pathlib import Path

from discover_lite.models import Agent, McpServer


def matches(data: object) -> bool:
    """True if the parsed JSON looks like an mcpServers config."""
    return isinstance(data, dict) and isinstance(data.get("mcpServers"), dict)


def parse(data: dict, path: Path) -> Agent:
    servers = []
    for name, entry in data["mcpServers"].items():
        servers.append(
            McpServer(
                name=name,
                # Local servers: command, args, env.
                command=entry.get("command"),
                args=entry.get("args", []),
                env=entry.get("env", {}),
                # Remote servers: url, headers.
                url=entry.get("url"),
                headers=entry.get("headers", {}),
            )
        )

    # An MCP client config lists servers, not tools, and has no instructions,
    # authentication or sharing settings, so those fields stay at their defaults.
    return Agent(
        id=path.name,
        name=path.name,
        platform="mcp_client",
        source_file=str(path),
        servers=servers,
    )
