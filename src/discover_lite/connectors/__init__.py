"""Connectors: read-only parsers that turn config files into Agents.

Connectors only translate. They never judge whether a setting is risky;
that is the job of the checks.
"""

import json
from pathlib import Path

from pydantic import ValidationError

from discover_lite.connectors import copilot_export, mcp_config, mcp_registry
from discover_lite.models import Agent

# Connectors where one file is one agent.
CONNECTORS = [mcp_config, copilot_export]

# The shape problems a connector can hit when a field has the wrong type
# (for example "args" is a string, not a list).
PARSE_ERRORS = (ValidationError, AttributeError, TypeError, KeyError)


def _read_json(path: Path) -> object | None:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _parse_one(data: object, path: Path) -> Agent | None:
    for connector in CONNECTORS:
        if connector.matches(data):
            try:
                return connector.parse(data, Path(path))
            except PARSE_ERRORS:
                return None
    return None


def load_any(path: Path) -> Agent | None:
    """Parse a one-agent config file with whichever connector recognises it.

    Returns None for unreadable files, invalid JSON, or shapes we do not know.
    """
    return _parse_one(_read_json(path), Path(path))


def load_agents(path: Path) -> list[Agent]:
    """Every agent in a file: many for a registry page, else zero or one."""
    data = _read_json(path)
    if mcp_registry.matches(data):
        try:
            return mcp_registry.parse_page(data, Path(path))
        except PARSE_ERRORS:
            return []
    agent = _parse_one(data, Path(path))
    return [agent] if agent is not None else []
