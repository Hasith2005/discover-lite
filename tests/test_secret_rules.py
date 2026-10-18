import pytest

from discover_lite.checks import _looks_generated
from discover_lite.secret_rules import _compile, find_vendor_key, load_rules, shannon_entropy


def test_almost_every_gitleaks_rule_loads():
    # 222 rules; generic-api-key is skipped on purpose and pkcs12-file
    # matches file names, not text. Every other rule must compile.
    ids = {rule["id"] for rule in load_rules()}
    assert len(ids) == 220
    assert {"stripe-access-token", "github-pat", "aws-access-token"} <= ids
    assert "generic-api-key" not in ids


def test_go_regex_differences_are_translated():
    # A (?i) part-way through and Go's \z, both rejected by Python 3.10 as written.
    pattern = _compile(r"abc_(?i)[a-z]{3}\z")
    assert pattern.search("abc_XYZ")
    assert not pattern.search("abc_XYZ more")


@pytest.mark.parametrize("text, expected", [("", 0.0), ("aaaa", 0.0), ("abcd", 2.0)])
def test_shannon_entropy(text, expected):
    assert shannon_entropy(text) == expected


@pytest.mark.parametrize(
    "value, rule",
    [
        ("sk_live_" + "FAKE0123456789abcdefghij", "stripe-access-token"),
        ("ghp_FAKE" + "0123456789abcdefghijklmnopqrstuv", "github-pat"),
        ("AKIA" + "FAKE234567QRSTUV", "aws-access-token"),
    ],
)
def test_find_vendor_key(value, rule):
    assert find_vendor_key(value) == (rule, value)


@pytest.mark.parametrize(
    "value",
    [
        "seu_token_aqui",
        # Right prefix, but not random enough for the rule's entropy limit.
        "ghp_" + "FAKE" * 9,
        # AWS's documented example key, on gitleaks' allowlist.
        "AKIAIOSFODNN7EXAMPLE",
    ],
)
def test_find_vendor_key_ignores_non_keys(value):
    assert find_vendor_key(value) is None


@pytest.mark.parametrize(
    "value",
    [
        "FAKE-9f8e7d6c5b4a3210",
        "sbp_FAKE0123456789abcdef0123456789abcdef",
        "fc-FAKE0123456789abcdef0123456789ab",
        "3|FAKEh7Kp2Qm9Xv4Lr8Tn6Wb1Yc5Zd0Je3Gs",  # Laravel Sanctum style "id|token".
    ],
)
def test_looks_generated(value):
    assert _looks_generated(value)


@pytest.mark.parametrize(
    "value",
    [
        "seu_token_aqui",  # Portuguese: "your token here".
        "sua_chave_aqui",
        "MyPassword123",  # Too short once separators are removed.
        "aaroneous-local-dev-key",  # Words only, no digits.
        "您的tushare令牌",  # Not ASCII.
        "aaaaaaaaaaaaaaaa1111",  # Long, letters and digits, but not random.
    ],
)
def test_does_not_look_generated(value):
    assert not _looks_generated(value)
