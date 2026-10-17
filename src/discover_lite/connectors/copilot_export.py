"""Connector for a synthetic Copilot Studio-style agent export.

Field names follow Microsoft's Copilot Studio agent inventory schema.
`instructions` and `topics` are our own additions to the format.
This connector only reads JSON.
"""

import re
from pathlib import Path

from discover_lite.models import Agent, Tool

AGENT_TYPE = "microsoft.copilotstudio/agents"

# Verbs that suggest an operation changes something.
WRITE_VERBS = {"add", "create", "update", "delete", "send", "post", "run"}


def matches(data: object) -> bool:
    """True if the parsed JSON looks like a Copilot Studio agent export."""
    return (
        isinstance(data, dict)
        and data.get("type") == AGENT_TYPE
        and isinstance(data.get("properties"), dict)
    )


def split_words(operation_id: str) -> list[str]:
    """Split a CamelCase name into lowercase words: "SendEmailV2" -> ["send", "email", "v", "2"]."""
    # Matches a capitalised word, a run of capitals (like "URL"), or digits.
    return [w.lower() for w in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+", operation_id)]


def infer_capability(operation_id: str) -> str:
    """Guess whether an operation reads or writes, from its name.

    This is a heuristic: the export does not say what an operation does, so we
    look for write-like verbs. We compare whole words, so "GetAddress" is not
    mistaken for "add".
    """
    if WRITE_VERBS & set(split_words(operation_id)):
        return "write"
    return "read"


def parse(data: dict, path: Path) -> Agent:
    props = data["properties"]

    tools = []
    for connector in props.get("powerPlatformConnectors", []):
        for op in connector.get("operations", []):
            # Knowledge operations are data sources, not actions, so skip them.
            if op.get("usedAs") == "Knowledge":
                continue
            tools.append(
                Tool(
                    name=op["operationId"],
                    capability=infer_capability(op["operationId"]),
                    # Missing key stays None: the export does not say.
                    requires_approval=op.get("requiresEndUserConsent"),
                )
            )

    return Agent(
        id=path.name,
        name=props.get("displayName", path.stem),
        platform="copilot_studio",
        source_file=str(path),
        instructions=props.get("instructions"),
        tools=tools,
        # Web search is the only untrusted knowledge source the export reveals.
        untrusted_knowledge=props.get("IsWebSearchEnabledForKnowledge"),
        # Kept as the platform's own string, e.g. "None" or "Microsoft Entra".
        authentication=props.get("authentication"),
        shared_org_wide=props.get("sharedWithViewers", {}).get("entireTenant"),
        topics=props.get("topics", {}),
    )
