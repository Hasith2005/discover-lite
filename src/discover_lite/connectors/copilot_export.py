"""Connector for a synthetic Copilot Studio-style agent export.

Field names follow Microsoft's Copilot Studio agent inventory schema.
`instructions`, `topics` and each operation's `method` are our own additions
to the format.
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

# HTTP methods from a connector's OpenAPI definition. These describe what the
# operation does, so they are a better signal than its name. An API can still
# misuse them (a GET that deletes), so a write word in the name still wins.
METHOD_CAPABILITY = {
    "GET": "read", "HEAD": "read",
    "POST": "write", "PUT": "write", "PATCH": "write", "DELETE": "write",
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


def classify(operation_id: str, method: str | None) -> str:
    """Combine the HTTP method (if the export has one) with the name heuristic.

    Fails closed: if either source says "write", the answer is "write".
    Otherwise either source saying "read" is enough. A method we do not know,
    or no method at all, leaves the name heuristic to decide.
    """
    from_name = infer_capability(operation_id)
    from_method = METHOD_CAPABILITY.get(method.upper()) if isinstance(method, str) else None
    if "write" in (from_name, from_method):
        return "write"
    if "read" in (from_name, from_method):
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
                    capability=classify(op["operationId"], op.get("method")),
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
