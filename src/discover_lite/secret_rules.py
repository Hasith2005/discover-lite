"""Vendor key formats, read from gitleaks' published rules (rules/gitleaks.toml).

gitleaks maintains regexes for about 220 kinds of key (Stripe, GitHub, AWS,
Slack and so on). We use them for one question about a value: "is this a known
vendor's key, and which?" No key format is invented here.
"""

import math
import re
import warnings
from collections import Counter
from functools import cache
from pathlib import Path

try:
    import tomllib  # Python 3.11 and later.
except ModuleNotFoundError:
    import tomli as tomllib  # The same parser as a package, for Python 3.10.

RULES_FILE = Path(__file__).parent / "rules" / "gitleaks.toml"

# gitleaks' catch-all rule looks for any secret-sounding word followed by any
# value. secret_in_config does that job itself, so only vendor rules are used.
SKIPPED_RULES = {"generic-api-key"}


def shannon_entropy(text: str) -> float:
    """Average bits of information per character.

    About 4 to 6 for a random key, lower for words: "aaaa" is 0, "abcd" is 2.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def _compile(pattern: str) -> re.Pattern:
    """Compile a gitleaks regex (written for Go) with Python's re.

    Two differences matter. Go writes "end of text" as \\z, Python as \\Z. Go
    allows (?i) part-way through a pattern, which Python 3.10 rejects: we drop
    the inner (?i) and make the whole pattern case-insensitive instead, which
    can only match more, never less.
    """
    pattern = pattern.replace(r"\z", r"\Z")
    flags = 0
    if "(?i)" in pattern[1:]:  # A (?i) that is not at the very start.
        pattern = pattern.replace("(?i)", "")
        flags = re.IGNORECASE
    with warnings.catch_warnings():
        # Some patterns trigger Python's harmless "possible nested set" warning.
        warnings.simplefilter("ignore", FutureWarning)
        return re.compile(pattern, flags)


@cache  # Read and compile the rules once.
def load_rules() -> list[dict]:
    """Each usable rule as {"id", "keywords", "regex", "entropy", "secret_group", "allow"}."""
    config = tomllib.loads(RULES_FILE.read_text(encoding="utf-8"))
    # Values gitleaks never reports, such as "true" or "${VAR}".
    global_allow = [_compile(p) for p in config["allowlist"]["regexes"]]
    rules = []
    for rule in config["rules"]:
        # A few rules match file names, not text, so they have no regex.
        if rule["id"] in SKIPPED_RULES or "regex" not in rule:
            continue
        # Known example values for this vendor, e.g. keys from public docs.
        allow = [_compile(p) for a in rule.get("allowlists", []) for p in a.get("regexes", [])]
        rules.append({
            "id": rule["id"],
            "keywords": [k.lower() for k in rule.get("keywords", [])],
            "regex": _compile(rule["regex"]),
            "entropy": rule.get("entropy", 0),
            "secret_group": rule.get("secretGroup"),
            "allow": global_allow + allow,
        })
    return rules


def _secret_part(rule: dict, match: re.Match) -> str:
    """The part of a match that is the key: the rule's secretGroup if it has
    one, else the first group (gitleaks' convention), else the whole match."""
    if rule["secret_group"]:
        return match.group(rule["secret_group"])
    if match.groups() and match.group(1):
        return match.group(1)
    return match.group()


def find_vendor_key(text: str) -> tuple[str, str] | None:
    """(rule id, key) for the first gitleaks rule that finds a key in text, else None."""
    for rule in load_rules():
        # Like gitleaks, try a rule only if the text holds one of its keywords
        # (usually the key's prefix). Without this, a rule that accepts any 40
        # hex characters fired on git commit hashes in package names.
        if rule["keywords"] and not any(k in text.lower() for k in rule["keywords"]):
            continue
        match = rule["regex"].search(text)
        if not match:
            continue
        key = _secret_part(rule, match)
        # gitleaks' own extra tests: random enough, and not a known example.
        if shannon_entropy(key) < rule["entropy"]:
            continue
        if any(allowed.search(key) for allowed in rule["allow"]):
            continue
        return rule["id"], key
    return None
