import json

import pytest

from discover_lite import fetch_registry


@pytest.fixture
def fake_registry(monkeypatch):
    """A registry of 1,000 entries served from memory, so no network is used.

    Returns the page sizes that were asked for.
    """
    asked = []

    def fake_page(cursor, size):
        asked.append(size)
        start = int(cursor or 0)
        servers = [{"server": {"name": f"srv-{i}"}} for i in range(start, min(start + size, 1000))]
        more = start + size < 1000
        return json.dumps({"servers": servers, "metadata": {"nextCursor": str(start + size) if more else None}}).encode()

    monkeypatch.setattr(fetch_registry, "fetch_page", fake_page)
    monkeypatch.setattr(fetch_registry.time, "sleep", lambda seconds: None)
    return asked


def test_limit_fetches_exactly_that_many(tmp_path, fake_registry):
    assert fetch_registry.fetch(tmp_path, 250, echo=lambda line: None) == 250
    # Two full pages, then only the 50 still needed.
    assert fake_registry == [100, 100, 50]
    saved = sum(len(json.loads(p.read_text())["servers"]) for p in tmp_path.glob("page-*.json"))
    assert saved == 250


def test_limit_smaller_than_a_page(tmp_path, fake_registry):
    assert fetch_registry.fetch(tmp_path, 5, echo=lambda line: None) == 5
    assert fake_registry == [5]


def test_zero_fetches_everything(tmp_path, fake_registry):
    assert fetch_registry.fetch(tmp_path, 0, echo=lambda line: None) == 1000
    assert fake_registry == [100] * 10
