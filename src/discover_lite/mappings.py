"""Framework mappings for each check, read from mappings.yaml."""

from functools import cache
from pathlib import Path

import yaml

MAPPINGS_FILE = Path(__file__).parent / "mappings.yaml"


@cache  # Read the file once, however many findings ask for it.
def load_mappings() -> dict[str, dict]:
    """Check id -> its mapping (title, category, owasp_llm_2026, atlas, nist_ai_rmf, why)."""
    # safe_load builds only plain data (dicts, lists, strings), never objects.
    return yaml.safe_load(MAPPINGS_FILE.read_text(encoding="utf-8"))
