"""Connector for an AWS Bedrock agent, as returned by the bedrock-agent API.

The real API needs several read-only calls per agent: GetAgent, then
ListAgentActionGroups and GetAgentActionGroup for each action group. Our file
bundles their responses, which is our own choice of format:

    {"agent": <GetAgent "agent">, "actionGroups": [<GetAgentActionGroup "agentActionGroup">, ...]}

Field names inside each part are AWS's own. This connector only reads JSON.
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
    """True if the parsed JSON looks like our bundle of Bedrock agent responses."""
    return (
        isinstance(data, dict)
        and isinstance(data.get("agent"), dict)
        and "agentId" in data["agent"]
    )


def _confirmation(value: object) -> bool | None:
    """Bedrock's "ENABLED"/"DISABLED" as True/False; anything else is None."""
    return {"ENABLED": True, "DISABLED": False}.get(value)


def _openapi_tools(payload: str) -> list[Tool]:
    """One tool per operation in an inline OpenAPI schema (JSON only).

    The HTTP method says what each operation does, so here the capability
    comes from the method, with the name as a fail-closed second opinion.
    """
    try:
        spec = json.loads(payload)
    except json.JSONDecodeError:
        return []  # A YAML schema, or not a schema at all: nothing we can read.
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
    for group in data.get("actionGroups", []):
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
