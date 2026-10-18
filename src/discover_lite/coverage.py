"""Field coverage: which security signals each platform actually gives us.

For every platform in a scan, count on how many of its agents each Agent field
is populated. A field that is never populated on a platform is a signal the
platform does not expose, which no check can make up for.
"""

from discover_lite.models import Agent

# Agent fields that carry a security signal, with a plain label for each.
FIELDS = {
    "instructions": "Instructions",
    "tools": "Tools",
    "servers": "MCP servers",
    "untrusted_knowledge": "Untrusted knowledge flag",
    "authentication": "Authentication setting",
    "shared_org_wide": "Sharing setting",
    "topics": "Topics",
    "guardrail": "Guardrail setting",
}


def is_populated(value: object) -> bool:
    """Not None and not empty. False counts: it is an explicit answer."""
    if value is None:
        return False
    if isinstance(value, (str, list, dict)):
        return len(value) > 0
    return True


def coverage(agents: list[Agent]) -> dict[str, dict[str, tuple[int, int]]]:
    """Platform -> {field label -> (agents with it populated, agents on that platform)}.

    One extra row, "Tool approval setting", counts tools rather than agents:
    how many tools say whether they need approval, out of all tools.
    """
    platforms = sorted({a.platform for a in agents})
    table = {}
    for platform in platforms:
        group = [a for a in agents if a.platform == platform]
        row = {
            label: (sum(is_populated(getattr(a, field)) for a in group), len(group))
            for field, label in FIELDS.items()
        }
        tools = [t for a in group for t in a.tools]
        row["Tool approval setting"] = (sum(t.requires_approval is not None for t in tools), len(tools))
        table[platform] = row
    return table


def cell(populated: int, total: int) -> str:
    """"3/4", or "-" when there is nothing to count."""
    return f"{populated}/{total}" if total else "-"
