"""Data models shared by connectors, checks and the CLI.

A note on None: throughout these models, None means "the platform does not
say". It is different from False. For example, `requires_approval=False`
means the config explicitly turns approval off, while `requires_approval=None`
means the config has no such setting at all. Checks must only fire on an
explicit value and must never treat a missing field as a failure.
"""

from typing import Literal

from pydantic import BaseModel


class Tool(BaseModel):
    """One action an agent can call."""

    name: str
    description: str = ""
    capability: Literal["read", "write", "execute", "unknown"] = "unknown"
    requires_approval: bool | None = None


class McpServer(BaseModel):
    """One MCP server entry in a client config.

    Local servers use command, args and env. Remote servers use url and headers.
    The last two fields are only filled in for MCP Registry entries.
    """

    name: str
    command: str | None = None
    args: list[str] = []
    env: dict[str, str] = {}
    url: str | None = None
    headers: dict[str, str] = {}
    # Package registry the server comes from, e.g. "npm" or "pypi".
    registry_type: str | None = None
    # Names of environment variables the server declares as secret. Declaring
    # a secret is the right way to ask for one, so this is never a finding;
    # it is recorded for statistics only.
    declared_secrets: list[str] = []


class Agent(BaseModel):
    """One agent (or MCP client) as read from one config file."""

    id: str
    name: str
    platform: Literal["mcp_client", "copilot_studio", "mcp_registry"]
    source_file: str
    instructions: str | None = None
    tools: list[Tool] = []
    servers: list[McpServer] = []
    untrusted_knowledge: bool | None = None
    authentication: str | None = None
    shared_org_wide: bool | None = None
    # Topic name -> list of trigger phrases.
    topics: dict[str, list[str]] = {}


class Finding(BaseModel):
    """One problem a check found in one agent."""

    check_id: str
    agent_id: str
    severity: Literal["low", "medium", "high"]
    evidence: str
    recommendation: str
