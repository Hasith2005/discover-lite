"""Posture checks: pure functions that take an Agent and return Findings.

Each check's id is its function name. Checks are deterministic rules, and they
only fire on explicit values: a field that is None ("the platform does not
say") never counts as a failure.
"""

import re
from pathlib import Path
from urllib.parse import urlparse

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from discover_lite.models import Agent, Finding

# A reference to a value stored elsewhere, which is the safe way to pass a
# secret, so it is not a finding: "${API_KEY}", "${env:API_KEY}" or
# "${input:token}" (VS Code), "$API_KEY", "%API_KEY%" (Windows), "{{api_key}}".
REFERENCE = re.compile(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|\{\{[^}]+\}\}")

# Text that marks a value as a placeholder someone is meant to replace, such as
# "YOUR_API_KEY", "<token>", "xxxx", "sk-..." or "replace-me". Real configs
# copied from READMEs are full of these, and they are not secrets.
PLACEHOLDER = re.compile(
    r"your|<[^>]*>|\[[^\]]*\]|x{4,}|\*{3,}|\.\.\.|example|placeholder|"
    r"change[_-]?me|replace|insert|here|todo|redacted|dummy|sample",
    re.IGNORECASE,
)

# Values that are a default or a word, not a chosen secret.
DEFAULT_VALUES = {"password", "secret", "token", "apikey", "api_key", "admin", "root", "changeme"}

# Name endings that mean the value describes a secret rather than being one,
# e.g. AUTH_METHOD, TOKEN_URL, KEY_FILE.
SETTING_NAME_ENDINGS = (
    "_url", "_uri", "_path", "_file", "_dir", "_method", "_type", "_mode",
    "_enabled", "_provider", "_host", "_port",
)

# Real secrets are long; shorter values under a secret-sounding name are
# usually settings like "true" or "local".
MIN_SECRET_LENGTH = 8

# Parts of a name that suggest the value is a secret. Matched as substrings of
# the lowercased name, so "DB_PASSWORD" and "Authorization" both match.
SECRET_NAME_WORDS = ("key", "token", "secret", "password", "auth", "credential")

# Well-known key formats: OpenAI/Anthropic style, GitHub tokens (classic and
# fine-grained), AWS access key id, Slack token, Google API key.
# Each must start at a word boundary: without it, "sk-" matched inside
# package names such as "breakerdesk-electrician-tools" and "task-graph-mcp".
_START = r"(?<![A-Za-z0-9])"
KNOWN_KEY_FORMATS = [
    re.compile(_START + r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(_START + r"ghp_[A-Za-z0-9]{36}"),
    re.compile(_START + r"github_pat_[A-Za-z0-9_]{22,}"),
    re.compile(_START + r"AKIA[0-9A-Z]{16}"),
    re.compile(_START + r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(_START + r"AIza[0-9A-Za-z_-]{35}"),
]

# Commands that download and run a package in one step.
PACKAGE_RUNNERS = {"npx", "uvx", "bunx", "pnpx"}

# Runner flags whose value is the package to fetch: "npx -p pkg cmd",
# "npx --package=pkg cmd", "uvx --from pkg cmd".
PACKAGE_FLAGS = {"-p", "--package", "--from"}

# Other runner flags that take a value, which must be skipped over.
VALUE_FLAGS = {"--with", "--python", "--index-url"}

# Exact versions: "pkg@1.2.3" or "@scope/pkg@1.2.3" (npm style, optional
# pre-release like "-beta.1"), or "pkg==1.2.3" (Python style, with the
# optional pre-release, post-release and dev parts Python versions allow,
# e.g. "0.1.0a4", "0.1.0rc2", "1.0.post1", "3.0.0.dev1").
NPM_PINNED = re.compile(r"(@[^/@\s]+/)?[^@\s]+@\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?")
PYTHON_PINNED = re.compile(r"[^=\s]+==\d+(\.\d+)*((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?")

# Hosts on the same machine, where plain HTTP never crosses the network.
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

MIN_INSTRUCTION_WORDS = 10

# Two topics whose trigger phrases are at least this similar (cosine similarity
# of their TF-IDF vectors, 0 to 1) are flagged. Tuned on the fixtures and a
# few hand-made pairs: with English stop words removed, clearly different
# topics scored 0.00 and overlapping ones 0.17 to 0.55.
TOPIC_OVERLAP_THRESHOLD = 0.15

# How many shared words to name in the evidence.
MAX_SHARED_WORDS = 5


def redact(value: str) -> str:
    """Hide a secret: keep the first three characters, e.g. "FAKE_TOKEN" -> "FAK****"."""
    return value[:3] + "****"


def _is_real_value(value: str) -> bool:
    """False for empty values, references to other places, and placeholders.

    A reference anywhere in the value counts, e.g. "${HOME}/keys/a.json".
    """
    return (
        bool(value)
        and not REFERENCE.search(value)
        and not PLACEHOLDER.search(value)
        and value.lower() not in DEFAULT_VALUES
    )


def _looks_like_secret(name: str, value: str) -> bool:
    if not _is_real_value(value):
        return False
    if any(pattern.search(value) for pattern in KNOWN_KEY_FORMATS):
        return True
    if not any(word in name.lower() for word in SECRET_NAME_WORDS):
        return False
    if name.lower().endswith(SETTING_NAME_ENDINGS):
        return False
    # A secret-sounding name, but the value may still be a setting, not a secret.
    is_setting = (
        len(value) < MIN_SECRET_LENGTH
        or value.lower() in ("true", "false")
        or value.isdigit()
        # A URL or a file path, e.g. AUTH_URL or KEY_FILE. A path to a key file
        # is not the key itself.
        or value.startswith(("http://", "https://", "/", "~", "./", "../"))
        or re.match(r"[A-Za-z]:\\", value) is not None  # Windows path like C:\
    )
    return not is_setting


def secret_in_config(agent: Agent) -> list[Finding]:
    """A secret written directly into an MCP server's env, headers or args."""
    findings = []
    for server in agent.servers:
        named_values = [("env", k, v) for k, v in server.env.items()]
        named_values += [("header", k, v) for k, v in server.headers.items()]
        for where, name, raw in named_values:
            # "Bearer abc" -> "abc", so we judge the token itself.
            value = raw.removeprefix("Bearer ")
            if _looks_like_secret(name, value):
                findings.append(
                    Finding(
                        check_id="secret_in_config",
                        agent_id=agent.id,
                        severity="high",
                        evidence=f"Server '{server.name}' {where} {name} = {redact(value)}",
                        recommendation="Move the value into an environment variable and reference it as ${VAR}.",
                    )
                )
        # Arguments have no names, so only known key formats count here.
        for arg in server.args:
            for pattern in KNOWN_KEY_FORMATS:
                match = pattern.search(arg)
                if match and _is_real_value(match.group()):
                    findings.append(
                        Finding(
                            check_id="secret_in_config",
                            agent_id=agent.id,
                            severity="high",
                            evidence=f"Server '{server.name}' argument contains a key: {redact(match.group())}",
                            recommendation="Pass the key through an environment variable, not a command-line argument.",
                        )
                    )
    return findings


def _package_argument(args: list[str]) -> str | None:
    """The package a runner will fetch, or None if there is none to judge."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in PACKAGE_FLAGS:
            return args[i + 1] if i + 1 < len(args) else None
        # "--package=pkg" style: the package is after the "=".
        flag, _, value = arg.partition("=")
        if value and flag in PACKAGE_FLAGS:
            return value
        if arg in VALUE_FLAGS:
            i += 2  # Skip the flag and its value.
            continue
        if not arg.startswith("-"):
            return arg
        i += 1
    return None


def _is_pinned(package: str) -> bool:
    return bool(NPM_PINNED.fullmatch(package) or PYTHON_PINNED.fullmatch(package))


def unpinned_package(agent: Agent) -> list[Finding]:
    """A package runner (npx, uvx, ...) fetching a package with no exact version."""
    findings = []
    for server in agent.servers:
        # Path(...).name turns "/usr/bin/npx" into "npx".
        if server.command is None or Path(server.command).name not in PACKAGE_RUNNERS:
            continue
        package = _package_argument(server.args)
        if package is None:
            continue
        if not _is_pinned(package):
            findings.append(
                Finding(
                    check_id="unpinned_package",
                    agent_id=agent.id,
                    severity="medium",
                    evidence=f"Server '{server.name}' runs '{server.command} {package}' with no exact version",
                    recommendation="Pin an exact version, e.g. pkg@1.2.3, so a new release cannot change what runs.",
                )
            )
    return findings


def insecure_remote_server(agent: Agent) -> list[Finding]:
    """A remote MCP server reached over plain HTTP, or with no Authorization header."""
    findings = []
    for server in agent.servers:
        if server.url is None:
            continue
        url = urlparse(server.url)
        # Servers on this machine are skipped: traffic never leaves it.
        if url.hostname in LOCAL_HOSTS:
            continue
        if url.scheme == "http":
            findings.append(
                Finding(
                    check_id="insecure_remote_server",
                    agent_id=agent.id,
                    severity="high",
                    evidence=f"Server '{server.name}' uses plain HTTP: {server.url}",
                    recommendation="Use https:// so traffic and credentials are encrypted.",
                )
            )
        # The registry does not record auth details, so a missing header there
        # means "does not say", not "no authentication".
        if agent.platform == "mcp_registry":
            continue
        # Header names are case-insensitive in HTTP.
        if not any(name.lower() == "authorization" for name in server.headers):
            findings.append(
                Finding(
                    check_id="insecure_remote_server",
                    agent_id=agent.id,
                    severity="low",
                    evidence=f"Server '{server.name}' sends no Authorization header (it may use OAuth instead)",
                    recommendation="Confirm the server requires authentication.",
                )
            )
    return findings


def missing_scope(agent: Agent) -> list[Finding]:
    """Instructions that are empty or too short to limit what the agent does."""
    # MCP client configs have no instructions field at all, and None means the
    # platform does not say, so neither case counts as a failure.
    if agent.platform == "mcp_client" or agent.instructions is None:
        return []
    word_count = len(agent.instructions.split())
    if word_count >= MIN_INSTRUCTION_WORDS:
        return []
    return [
        Finding(
            check_id="missing_scope",
            agent_id=agent.id,
            severity="medium",
            evidence=f"Instructions are {word_count} words long (fewer than {MIN_INSTRUCTION_WORDS})",
            recommendation="Write instructions that state the agent's purpose, limits and what it must refuse.",
        )
    ]


def no_human_in_loop(agent: Agent) -> list[Finding]:
    """A write or execute tool that explicitly runs without approval."""
    return [
        Finding(
            check_id="no_human_in_loop",
            agent_id=agent.id,
            severity="high",
            evidence=f"Tool '{tool.name}' ({tool.capability}) runs without approval",
            recommendation="Require user consent or approval before this tool runs.",
        )
        for tool in agent.tools
        # "is False", not "not ...": None means unknown and must not fire.
        if tool.capability in ("write", "execute") and tool.requires_approval is False
    ]


def open_access(agent: Agent) -> list[Finding]:
    """An agent anyone can use: no authentication, or shared with the whole organisation."""
    findings = []
    # The string "None" is the platform's setting for no authentication.
    # Python None would mean the setting is missing, which does not fire.
    if agent.authentication == "None":
        findings.append(
            Finding(
                check_id="open_access",
                agent_id=agent.id,
                severity="high",
                evidence='Authentication is set to "None"',
                recommendation="Require sign-in, e.g. Microsoft Entra.",
            )
        )
    if agent.shared_org_wide is True:
        findings.append(
            Finding(
                check_id="open_access",
                agent_id=agent.id,
                severity="medium",
                evidence="Shared with the entire organisation",
                recommendation="Share only with the groups that need this agent.",
            )
        )
    return findings


def unclassified_tool(agent: Agent) -> list[Finding]:
    """A tool whose name we could not classify, running without approval.

    The capability comes from a word-list heuristic. When it returns "unknown",
    we cannot tell whether the tool is risky, so we say so instead of guessing.
    """
    return [
        Finding(
            check_id="unclassified_tool",
            agent_id=agent.id,
            severity="low",
            evidence=f"Tool '{tool.name}' could not be classified as read or write and runs without approval",
            recommendation="Review what this tool does; if it changes data, require approval.",
        )
        for tool in agent.tools
        # As elsewhere, only an explicit False counts; None does not fire.
        if tool.capability == "unknown" and tool.requires_approval is False
    ]


def prompt_injection_exposure(agent: Agent) -> list[Finding]:
    """An agent that reads untrusted content and can also take actions.

    Text from the web can carry hidden instructions, and an agent that obeys
    them with a write or execute tool can act for the attacker.
    """
    # "is not True", not "not ...": None means the platform does not say.
    if agent.untrusted_knowledge is not True:
        return []
    # "unknown" does not count here; unclassified_tool covers that case.
    action_tools = [tool.name for tool in agent.tools if tool.capability in ("write", "execute")]
    if not action_tools:
        return []
    return [
        Finding(
            check_id="prompt_injection_exposure",
            agent_id=agent.id,
            severity="high",
            evidence=f"Reads untrusted content (e.g. web search) and can act with: {', '.join(action_tools)}",
            recommendation="Turn off untrusted knowledge sources, or require approval for every action tool.",
        )
    ]


def topic_overlap(agent: Agent) -> list[Finding]:
    """Two topics with similar trigger phrases, so the agent may pick the wrong one.

    Copilot Studio calls this "Multiple Topics Matched". Each topic's phrases
    are joined into one text, turned into a TF-IDF vector (words weighted by
    how rare they are across this agent's topics) and compared pairwise.
    """
    if len(agent.topics) < 2:
        return []
    names = list(agent.topics)
    texts = [" ".join(agent.topics[name]) for name in names]
    # Stop words like "my" and "I" would otherwise make unrelated topics look alike.
    vectorizer = TfidfVectorizer(stop_words="english")
    try:
        vectors = vectorizer.fit_transform(texts)
    except ValueError:
        return []  # No usable words at all, e.g. every phrase is empty.
    similarity = cosine_similarity(vectors)
    words = vectorizer.get_feature_names_out()

    findings = []
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            score = similarity[i, j]
            if score < TOPIC_OVERLAP_THRESHOLD:
                continue
            # A word's share of the score is its weight in one topic times its
            # weight in the other; words missing from either topic give 0.
            contribution = vectors[i].multiply(vectors[j]).toarray()[0]
            top = contribution.argsort()[::-1][:MAX_SHARED_WORDS]
            shared = [words[k] for k in top if contribution[k] > 0]
            findings.append(
                Finding(
                    check_id="topic_overlap",
                    agent_id=agent.id,
                    severity="medium",
                    evidence=(
                        f"Topics '{names[i]}' and '{names[j]}' have similar trigger phrases "
                        f"(similarity {score:.2f}); shared words: {', '.join(shared)}"
                    ),
                    recommendation="Make the trigger phrases distinct, or merge the topics into one.",
                )
            )
    return findings


ALL_CHECKS = [
    secret_in_config,
    unpinned_package,
    insecure_remote_server,
    missing_scope,
    no_human_in_loop,
    open_access,
    unclassified_tool,
    prompt_injection_exposure,
    topic_overlap,
]


def run_all(agent: Agent) -> list[Finding]:
    """Run every registered check on one agent."""
    return [finding for check in ALL_CHECKS for finding in check(agent)]
