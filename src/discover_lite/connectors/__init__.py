"""Connectors: read-only parsers that turn one config file into one Agent.

Connectors only translate. They never judge whether a setting is risky;
that is the job of the checks.
"""

import json
from pathlib import Path

from pydantic import ValidationError

from discover_lite.connectors import copilot_export, mcp_config
from discover_lite.models import Agent

CONNECTORS = [mcp_config, copilot_export]


def load_any(path: Path) -> Agent | None:
    """Parse a config file with whichever connector recognises its shape.

    Returns None for unreadable files, invalid JSON, or shapes we do not know.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    for connector in CONNECTORS:
        if connector.matches(data):
            try:
                return connector.parse(data, Path(path))
            # The file has the right outer shape but a field has the wrong
            # type (for example "args" is a string, not a list).
            except (ValidationError, AttributeError, TypeError):
                return None
    return None
