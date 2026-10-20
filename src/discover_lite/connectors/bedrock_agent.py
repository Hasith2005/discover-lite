"""Connector for an AWS Bedrock agent, as returned by the bedrock-agent API.

Each file is one saved response from a read-only call, unchanged:

    GetAgent             -> {"agent": {...}}
    GetAgentActionGroup  -> {"agentActionGroup": {...}}

The agent file is the one that becomes an Agent. Its action groups are the
GetAgentActionGroup responses in the same folder whose agentId and
agentVersion match the agent's, so file names do not matter. Every field
read here is in the Bedrock API reference; nothing is our own.
This connector only reads JSON.
"""

import json
from pathlib import Path

from discover_lite.connectors.copilot_export import classify
from discover_lite.models import Agent, Tool

# Bedrock's built-in action group that lets the agent write and run code.
CODE_INTERPRETER = "AMAZON.CodeInterpreter"

# Operations in an OpenAPI file sit under each path, keyed by HTTP method.
OPENAPI_METHODS = {"get", "head", "post", "put", "patch", "delete"}


def matches(data: object) -> bool:
    """True if the parsed JSON is a saved GetAgent response."""
    return (
        isinstance(data, dict)
        and isinstance(data.get("agent"), dict)
        and "agentId" in data["agent"]
    )


def action_group(data: object) -> dict | None:
    """The action group in a saved GetAgentActionGroup response, or None."""
    if isinstance(data, dict) and isinstance(data.get("agentActionGroup"), dict):
        return data["agentActionGroup"]
    return None


def _action_groups(agent: dict, folder: Path) -> list[dict]:
    """The agent's action groups, from GetAgentActionGroup responses beside it."""
    groups = []
    for path in sorted(folder.glob("*.json")):
        try:
            group = action_group(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if (
            group is not None
            and group.get("agentId") == agent["agentId"]
            and group.get("agentVersion") == agent.get("agentVersion")
        ):
            groups.append(group)
    return groups


def _confirmation(value: object) -> bool | None:
    """Bedrock's "ENABLED"/"DISABLED" as True/False; anything else is None."""
    return {"ENABLED": True, "DISABLED": False}.get(value)


def _openapi_tools(payload: str) -> list[Tool]:
    """One tool per operation in an inline OpenAPI schema (JSON only)."""
    try:
        spec = json.loads(payload)
    except json.JSONDecodeError:
        return []  # A YAML schema, or not a schema at all: nothing we can read.
    return openapi_tools(spec)


def openapi_tools(spec: dict) -> list[Tool]:
    """One tool per operation in a parsed OpenAPI document.

    The HTTP method says what each operation does, so here the capability
    comes from the method, with the name as a fail-closed second opinion.
    """
    tools = []
    for path, operations in spec.get("paths", {}).items():
        for method, operation in operations.items():
            if method not in OPENAPI_METHODS:
                continue
            name = operation.get("operationId", f"{method.upper()} {path}")
            tools.append(
                Tool(
                    name=name,
                    description=operation.get("description", ""),
                    capability=classify(name, method),
                    # Confirmation for API schemas is not read here: None.
                )
            )
    return tools


def parse(data: dict, path: Path) -> Agent:
    agent = data["agent"]

    tools = []
    for group in _action_groups(agent, path.parent):
        # A disabled action group cannot be called, so it adds no tools.
        if group.get("actionGroupState") == "DISABLED":
            continue
        if group.get("parentActionGroupSignature") == CODE_INTERPRETER:
            # Runs code the model writes. Bedrock has no confirmation setting
            # for it, so approval stays None (the platform does not say).
            tools.append(Tool(name="CodeInterpreter", capability="execute"))
            continue
        # The function-details style: each function can require confirmation.
        for function in group.get("functionSchema", {}).get("functions", []):
            tools.append(
                Tool(
                    name=function["name"],
                    description=function.get("description", ""),
                    capability=classify(function["name"], None),
                    requires_approval=_confirmation(function.get("requireConfirmation")),
                )
            )
        # The OpenAPI style: operations come from an inline schema.
        payload = group.get("apiSchema", {}).get("payload")
        if isinstance(payload, str):
            tools.extend(_openapi_tools(payload))

    return Agent(
        id=path.name,
        name=agent.get("agentName", path.stem),
        platform="bedrock_agent",
        source_file=str(path),
        instructions=agent.get("instruction"),
        tools=tools,
        # GetAgent includes guardrailConfiguration only when one is attached,
        # so here a missing key does mean "no guardrail", not "does not say".
        guardrail="guardrailConfiguration" in agent,
        # Access is controlled by IAM policies, which GetAgent does not show,
        # so authentication and sharing stay None.
    )
