"""Offline tests for the GitHub fetcher's filtering. No network is used."""

import pytest

from discover_lite.fetch_github import BLOB_SHA, is_wanted


@pytest.mark.parametrize(
    "path, filename",
    [
        (".mcp.json", ".mcp.json"),
        ("config/claude_desktop_config.json", "claude_desktop_config.json"),
    ],
)
def test_is_wanted_keeps_real_configs(path, filename):
    assert is_wanted({"path": path}, filename)


@pytest.mark.parametrize(
    "path, filename",
    [
        # Not the exact file name.
        (".mcp.json.mac.example", ".mcp.json"),
        ("claude_desktop_config.json.bak", "claude_desktop_config.json"),
        # Documentation and test paths.
        ("examples/claude_desktop_config.json", "claude_desktop_config.json"),
        ("docs/.mcp.json", ".mcp.json"),
        ("tests/fixtures/.mcp.json", ".mcp.json"),
        ("templates/.mcp.json", ".mcp.json"),
    ],
)
def test_is_wanted_skips_examples_and_other_names(path, filename):
    assert not is_wanted({"path": path}, filename)


def test_blob_sha_rejects_path_tricks():
    assert BLOB_SHA.fullmatch("0168d04e1659e8a8d84886549ee200b996c475c4")
    # Anything that could escape the output folder is refused.
    assert not BLOB_SHA.fullmatch("../../etc/passwd")
    assert not BLOB_SHA.fullmatch("0168d04e1659e8a8d84886549ee200b996c475c4/../x")
