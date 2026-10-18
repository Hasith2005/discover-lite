"""Download public MCP client configs from GitHub code search.

This is the only module besides the registry fetcher that touches the network,
and it only runs from the explicit `fetch-github` command. It uses the `gh` CLI
(already logged in) so no token handling lives in this code.

Downloaded files are untrusted data. We only save their bytes; we never run
anything from them. Scanning them later is offline and parses JSON only.
"""

import base64
import json
import re
import subprocess
import time
from datetime import date
from pathlib import Path

# One search per MCP client: (client, file name, search words). VS Code's
# mcp.json uses a "servers" key; the others use "mcpServers".
SEARCHES = [
    ("Claude Code", ".mcp.json", "mcpServers"),
    ("Claude Desktop", "claude_desktop_config.json", "mcpServers"),
    ("Cursor", "mcp.json", "mcpServers path:.cursor"),
    ("VS Code", "mcp.json", "servers path:.vscode"),
    ("Windsurf", "mcp_config.json", "mcpServers"),
    ("Cline", "cline_mcp_settings.json", "mcpServers"),
]

# Code search returns at most 1,000 results per query. Splitting each search
# by file size (in bytes) gives separate queries, each with its own 1,000.
SIZE_RANGES = ["<300", "300..600", "600..1000", "1000..2000", ">2000"]

# Paths that look like documentation rather than a config someone uses.
EXAMPLE_PATH = re.compile(r"example|sample|template|demo|docs?/|tests?/|fixtures?/", re.IGNORECASE)

# GitHub allows about 10 code searches a minute, so wait between pages.
SEARCH_PAUSE_SECONDS = 7
DOWNLOAD_PAUSE_SECONDS = 0.5
RATE_LIMIT_WAIT_SECONDS = 60

# A config is a few kilobytes; anything bigger is not what we are looking for.
MAX_FILE_BYTES = 100_000

# A git blob id: 40 hex characters. Checked before using it as a file name, so
# a strange API response can never write outside the output folder.
BLOB_SHA = re.compile(r"[0-9a-f]{40}")


def gh_api(*args: str) -> dict:
    """Call `gh api` and return the parsed JSON response."""
    result = subprocess.run(["gh", "api", *args], capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def search_page(words: str, filename: str, size: str, page: int) -> list[dict]:
    """One page (up to 100 results) of code search for one file name and size range."""
    args = (
        "-X", "GET", "search/code",
        "-f", f"q={words} filename:{filename} size:{size}",
        "-f", "per_page=100",
        "-f", f"page={page}",
    )
    try:
        response = gh_api(*args)
    except subprocess.CalledProcessError:
        # Usually the rate limit: wait a minute and try once more.
        time.sleep(RATE_LIMIT_WAIT_SECONDS)
        response = gh_api(*args)
    return response.get("items", [])


def download_blob(repo: str, sha: str) -> bytes:
    """The raw bytes of one file, fetched by its git blob id."""
    response = gh_api(f"repos/{repo}/git/blobs/{sha}")
    return base64.b64decode(response["content"])


def is_wanted(item: dict, filename: str) -> bool:
    """Keep exact file names only, and skip example-like paths."""
    path = item["path"]
    return Path(path).name == filename and not EXAMPLE_PATH.search(path)


def fetch(out_dir: Path, limit: int, echo=print) -> int:
    """Download up to `limit` new configs, split evenly across SEARCHES.

    Files are saved as <blob sha>.json. A git blob id is a hash of the file's
    contents, so identical copies (forks, copied templates) share one id and
    are saved only once, and files from an earlier run are not fetched again.
    Repository names are not stored anywhere.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    per_search = limit // len(SEARCHES)
    counts = {}

    for client, filename, words in SEARCHES:
        saved = skipped = duplicates = 0
        for size in SIZE_RANGES:
            # 10 pages of 100 is the most one query returns.
            for page in range(1, 11):
                if saved >= per_search:
                    break
                items = search_page(words, filename, size, page)
                time.sleep(SEARCH_PAUSE_SECONDS)
                if not items:
                    break
                for item in items:
                    if saved >= per_search:
                        break
                    sha = item["sha"]
                    if not is_wanted(item, filename) or not BLOB_SHA.fullmatch(sha):
                        skipped += 1
                        continue
                    target = out_dir / f"{sha}.json"
                    if target.exists():
                        duplicates += 1
                        continue
                    try:
                        content = download_blob(item["repository"]["full_name"], sha)
                    except subprocess.CalledProcessError:
                        skipped += 1  # Deleted or private since it was indexed.
                        continue
                    finally:
                        time.sleep(DOWNLOAD_PAUSE_SECONDS)
                    if len(content) > MAX_FILE_BYTES:
                        skipped += 1
                        continue
                    target.write_bytes(content)
                    saved += 1
                echo(f"{client} ({filename}, size {size}): page {page}, {saved} saved so far")
        counts[client] = {"filename": filename, "saved": saved, "skipped": skipped, "duplicates": duplicates}

    write_record(out_dir, counts)
    return sum(c["saved"] for c in counts.values())


def write_record(out_dir: Path, counts: dict) -> None:
    """Add a record of this run (when, how, how many) to FETCHED.md."""
    total = len(list(out_dir.glob("*.json")))
    lines = [
        "",
        f"## Run on {date.today().isoformat()}",
        "",
        "Source: GitHub code search API (`search/code`), one query per client and file-size range, best-match order.",
        "Kept: exact file names only; paths matching example, sample, template, demo, docs, tests or fixtures skipped.",
        "Duplicates: files are named by git blob id, so identical contents (and files from earlier runs) are saved once.",
        "",
        "| Client | File name | Saved | Skipped | Duplicates |",
        "|---|---|---|---|---|",
    ]
    for client, c in counts.items():
        lines.append(f"| {client} | {c['filename']} | {c['saved']} | {c['skipped']} | {c['duplicates']} |")
    lines += ["", f"Files in the folder after this run: {total}"]
    record = out_dir / "FETCHED.md"
    # Keep earlier runs' records; start the file with a title the first time.
    previous = record.read_text() if record.exists() else "# GitHub MCP config sample\n"
    record.write_text(previous + "\n".join(lines) + "\n")
