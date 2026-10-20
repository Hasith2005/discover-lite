"""Connector for a Microsoft Foundry agent, as returned by the Foundry Agent Service REST API.

The file is one saved response from a read-only call, unchanged:

    GET {endpoint}/agents/{agent_name}?api-version=v1                       -> AgentObject
    GET {endpoint}/agents/{agent_name}/versions/{version}?api-version=v1    -> AgentVersionObject

An AgentObject holds its newest version under "versions.latest". Every field
read here is in the Foundry REST reference
(learn.microsoft.com/rest/api/microsoft-foundry/aiproject); nothing is our own.
This connector only reads JSON.
"""

from pathlib import Path

from discover_lite.connectors.bedrock_agent import openapi_tools
from discover_lite.connectors.copilot_export import classify
from discover_lite.models import Agent, McpServer, Tool

# Tools that run code or commands the model writes.
EXECUTE_TYPES = {"code_interpreter", "shell", "local_shell"}

# Tools that bring in content from the open web, where anyone can plant
# instructions. Browser automation reads web pages as well as acting on them.
WEB_TYPES = {
    "web_search", "web_search_preview", "bing_grounding",
    "bing_custom_search_preview", "browser_automation_preview",
}

# Tools that only retrieve content for the model. Like Copilot Studio's
# knowledge sources, they are data sources, not actions.
RETRIEVAL_TYPES = {
    "file_search", "azure_ai_search", "web_search", "web_search_preview",
    "bing_grounding", "bing_custom_search_preview", "sharepoint_grounding_preview",
    "fabric_dataagent_preview", "memory_search_preview",
}


def _version(data: object) -> dict | None:
    """The AgentVersionObject in a saved response, or None if this is not one."""
    if not isinstance(data, dict):
        return None
    if data.get("object") == "agent" and isinstance(data.get("versions"), dict):
        data = data["versions"].get("latest")
    if isinstance(data, dict) and data.get("object") == "agent.version" and isinstance(data.get("definition"), dict):
        return data
    return None


def matches(data: object) -> bool:
    """True if the parsed JSON is a Foundry AgentObject or AgentVersionObject."""
    return _version(data) is not None


def _names(value: object) -> list[str]:
    """Tool names from a list of names or an MCPToolFilter's "tool_names"."""
    if isinstance(value, dict):
        value = value.get("tool_names")
    return [name for name in value or [] if isinstance(name, str)]


def _mcp_approval(require: object, name: str) -> bool | None:
    """Whether a call to this MCP tool needs approval.

    Foundry documents "always" as the default when require_approval is left
    out, so a missing setting is an explicit True. In the per-tool form, a
    tool named in neither list is not documented, so it stays None.
    """
    if require is None or require == "always":
        return True
    if require == "never":
        return False
    if isinstance(require, dict):
        if name in _names(require.get("always")):
            return True
        if name in _names(require.get("never")):
            return False
    return None


def _mcp_tools(tool: dict) -> list[Tool]:
    """The MCP tools a definition names, in allowed_tools or the approval lists.

    A server with neither exposes tools the definition does not list; finding
    them means connecting to the server, which a static scanner never does.
    """
    require = tool.get("require_approval")
    names = _names(tool.get("allowed_tools"))
    if isinstance(require, dict):
        names += _names(require.get("always")) + _names(require.get("never"))
    return [
        Tool(name=name, capability=classify(name, None), requires_approval=_mcp_approval(require, name))
        for name in dict.fromkeys(names)
    ]


def parse(data: dict, path: Path) -> Agent:
    version = _version(data)
    definition = version["definition"]

    tools = []
    servers = []
    for tool in definition.get("tools") or []:
        kind = tool.get("type")
        if kind in RETRIEVAL_TYPES:
            continue
        if kind == "function":
            # Function tools run in the caller's own code, which decides on
            # approval, so the definition does not say: None.
            tools.append(Tool(name=tool["name"], description=tool.get("description") or "", capability=classify(tool["name"], None)))
        elif kind == "azure_function":
            function = tool["azure_function"]["function"]
            tools.append(Tool(name=function["name"], description=function.get("description", ""), capability=classify(function["name"], None)))
        elif kind == "openapi":
            spec = tool["openapi"].get("spec")
            if isinstance(spec, dict):
                tools.extend(openapi_tools(spec))
        elif kind == "mcp":
            servers.append(
                McpServer(
                    name=tool["server_label"],
                    # A service connector (connector_id) has no URL.
                    url=tool.get("server_url"),
                    headers=tool.get("headers") or {},
                )
            )
            tools.extend(_mcp_tools(tool))
        elif kind in EXECUTE_TYPES:
            tools.append(Tool(name=kind, capability="execute"))
        elif isinstance(kind, str):
            # Other built-in tools (browser automation, A2A, image generation
            # and so on) are judged by their type name like any other tool.
            name = tool.get("name") or kind
            tools.append(Tool(name=name, capability=classify(name, None)))

    kinds = {tool.get("type") for tool in definition.get("tools") or []}
    return Agent(
        id=path.name,
        name=version.get("name", path.stem),
        platform="foundry_agent",
        source_file=str(path),
        # Only prompt agents have instructions; other kinds give None.
        instructions=definition.get("instructions"),
        tools=tools,
        servers=servers,
        # A web tool is untrusted content. Without one the definition still
        # does not say: MCP, OpenAPI and A2A tools can return web content too.
        untrusted_knowledge=True if kinds & WEB_TYPES else None,
        # rai_config attaches a content filter policy to the agent. Without it
        # the model deployment's own filter may still apply, and that is not
        # in the agent definition, so a missing rai_config is None, not False.
        guardrail=True if "rai_config" in definition else None,
        # Who can call the agent is Azure RBAC on the project, which these
        # responses do not show, so authentication and sharing stay None.
    )
