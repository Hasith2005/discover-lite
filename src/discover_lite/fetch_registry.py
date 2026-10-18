"""Download server definitions from the official MCP Registry.

Network access happens only here, from the explicit `fetch-registry` command.
Uses urllib from the standard library, so no extra dependency. Each page is
saved unchanged; the connector reads the saved pages later, offline.
"""

import json
import time
import urllib.parse
import urllib.request
from datetime import date
from pathlib import Path

API_URL = "https://registry.modelcontextprotocol.io/v0/servers"
PAGE_SIZE = 100
USER_AGENT = "discover-lite (research project)"
PAUSE_SECONDS = 1  # Be polite: one request at a time, with a short pause.


def fetch_page(cursor: str | None, size: int = PAGE_SIZE) -> bytes:
    """One page of up to `size` entries, as the raw bytes the API returned."""
    params = {"limit": size}
    if cursor:
        params["cursor"] = cursor
    url = f"{API_URL}?{urllib.parse.urlencode(params)}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def fetch(out_dir: Path, limit: int, echo=print) -> int:
    """Save pages until there is no next cursor, or exactly `limit` entries (0 = no limit)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cursor, entries, page = None, 0, 0
    while True:
        # Ask only for what is still needed, so the last page is not overfilled.
        size = min(PAGE_SIZE, limit - entries) if limit else PAGE_SIZE
        raw = fetch_page(cursor, size)
        page += 1
        # Saved exactly as received, so the data can be checked later.
        (out_dir / f"page-{page:04d}.json").write_bytes(raw)
        data = json.loads(raw)
        entries += len(data.get("servers", []))
        echo(f"page {page}: {entries} entries so far")
        cursor = data.get("metadata", {}).get("nextCursor")
        if not cursor or (limit and entries >= limit):
            break
        time.sleep(PAUSE_SECONDS)

    (out_dir / "FETCHED.md").write_text(
        "# MCP Registry sample\n\n"
        f"Fetched: {date.today().isoformat()}\n"
        f"URL: {API_URL}?limit={PAGE_SIZE}, following metadata.nextCursor\n"
        f"Pages: {page}\n"
        f"Entries (all versions): {entries}\n"
    )
    return entries
