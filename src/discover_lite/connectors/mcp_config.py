"""Connector for MCP client config files.

Claude Desktop (claude_desktop_config.json), Claude Code (.mcp.json), Cursor
(.cursor/mcp.json), Windsurf and Cline keep servers under an `mcpServers` key.
VS Code (.vscode/mcp.json) uses the same entries under a `servers` key. The
whole file describes one client, so it becomes one Agent.
This connector only reads JSON; it never starts or connects to a server.
"""

from pathlib import Path

from discover_lite.connectors.copilot_export import infer_capability
from discover_lite.models import Agent, McpServer, Tool

# Names clients use for a remote server's address: most use "url", Windsurf
# uses "serverUrl" and Gemini CLI uses "httpUrl".
URL_KEYS = ("url", "serverUrl", "httpUrl")


def _unwrap_cmd(command: object, args: list) -> tuple[object, list]:
    """On Windows, "cmd /c npx pkg" really runs "npx pkg"; return that.

    Only a single program name after /c is unwrapped. A longer shell line
    such as "cd x && python server.py" is left as it is.
    """
    if (
        isinstance(command, str)
        and command.lower() in ("cmd", "cmd.exe")
        and len(args) >= 2
        and str(args[0]).lower() == "/c"
        and " " not in str(args[1])
    ):
        return args[1], args[2:]
    return command, args


def _server_entries(data: object) -> dict | None:
    """The name -> entry mapping of servers, or None if this is not a client config."""
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("mcpServers"), dict):
        return data["mcpServers"]
    # "servers" alone is a common key, so for VS Code's format we also want
    # every entry to look like a server (a command or a url).
    servers = data.get("servers")
    if isinstance(servers, dict) and servers and all(
        isinstance(entry, dict) and ("command" in entry or "url" in entry)
        for entry in servers.values()
    ):
        return servers
    return None


def matches(data: object) -> bool:
    """True if the parsed JSON looks like an MCP client config."""
    return _server_entries(data) is not None


def parse(data: dict, path: Path) -> Agent:
    servers = []
    tools = []
    for name, entry in _server_entries(data).items():
        command, args = _unwrap_cmd(entry.get("command"), entry.get("args", []))
        servers.append(
            McpServer(
                name=name,
                # Local servers: command, args, env.
                command=command,
                args=args,
                env=entry.get("env", {}),
                # Remote servers: url, headers.
                url=next((entry[key] for key in URL_KEYS if key in entry), None),
                headers=entry.get("headers", {}),
            )
        )
        # Cline's "alwaysAllow" lists tools that run without asking the user.
        # It is the only place a client config names tools, and it is an
        # explicit "no approval" for each one.
        always_allow = entry.get("alwaysAllow", [])
        if isinstance(always_allow, list):
            for tool in always_allow:
                if isinstance(tool, str):
                    tools.append(Tool(name=tool, capability=infer_capability(tool), requires_approval=False))

    # An MCP client config has no instructions, authentication or sharing
    # settings, so those fields stay at their defaults.
    return Agent(
        id=path.name,
        # A file like .mcp.json has the same name in every project, so the
        # folder it sits in says which one this is.
        name=f"{path.parent.name}/{path.name}" if path.name.startswith(".") else path.name,
        platform="mcp_client",
        source_file=str(path),
        tools=tools,
        servers=servers,
    )
