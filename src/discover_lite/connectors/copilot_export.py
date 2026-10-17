"""Connector for a synthetic Copilot Studio-style agent export.

Field names follow Microsoft's Copilot Studio agent inventory schema.
`instructions` and `topics` are our own additions to the format.
This connector only reads JSON.
"""

import re
from pathlib import Path

from discover_lite.models import Agent, Tool

AGENT_TYPE = "microsoft.copilotstudio/agents"

# Words that suggest an operation changes something.
WRITE_WORDS = {
    "add", "create", "insert", "update", "edit", "modify", "patch", "set",
    "upsert", "replace", "rename", "move", "copy", "upload", "save", "write",
    "import", "delete", "remove", "purge", "clear", "archive", "cancel", "close",
    "send", "post", "reply", "forward", "share", "publish", "submit", "approve",
    "reject", "assign", "grant", "revoke", "invite", "transfer", "pay", "refund",
    "reset", "lock", "unlock", "enable", "disable", "mark", "flag", "apply",
    "run", "execute", "invoke", "trigger", "start", "stop", "restart",
}

# Words that suggest an operation only reads.
READ_WORDS = {
    "get", "list", "search", "find", "read", "query", "fetch", "lookup", "look",
    "view", "show", "retrieve", "download", "describe", "count", "browse",
}


def matches(data: object) -> bool:
    """True if the parsed JSON looks like a Copilot Studio agent export."""
    return (
        isinstance(data, dict)
        and data.get("type") == AGENT_TYPE
        and isinstance(data.get("properties"), dict)
    )


def split_words(operation_id: str) -> list[str]:
    """Split a name into lowercase words: "SendEmailV2" -> ["send", "email", "v", "2"].

    Works for CamelCase and snake_case ("send_email" -> ["send", "email"]).
    """
    # Matches a capitalised word, a run of capitals (like "URL"), or digits.
    return [w.lower() for w in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+", operation_id)]


def infer_capability(operation_id: str) -> str:
    """Guess whether an operation reads or writes, from its name.

    This is a heuristic: the export does not say what an operation does, so we
    look for known words. It fails closed:
    - any write word means "write", even if a read word is also present
      ("UpdateReadStatus" is a write);
    - otherwise any read word means "read";
    - anything else is "unknown", never "read", so a gap in the word lists
      shows up instead of hiding a risky tool.
    We compare whole words, so "GetAddress" is not mistaken for "add".
    """
    words = set(split_words(operation_id))
    if words & WRITE_WORDS:
        return "write"
    if words & READ_WORDS:
        return "read"
    return "unknown"


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
