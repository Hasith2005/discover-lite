import json
import re
from pathlib import Path

from typer.testing import CliRunner

from discover_lite.checks import ALL_CHECKS
from discover_lite.cli import app
from discover_lite.mappings import load_mappings

FIXTURES = Path(__file__).parent.parent / "fixtures"

OWASP_IDS = {f"LLM{n:02}" for n in range(1, 11)}
NIST_FUNCTIONS = {"Govern", "Map", "Measure", "Manage"}
# An ATLAS technique id, e.g. "AML.T0051", or a sub-technique, e.g. "AML.T0051.001".
ATLAS_ID = re.compile(r"AML\.T\d{4}(\.\d{3})?")


def test_every_check_has_a_mapping():
    assert set(load_mappings()) == {check.__name__ for check in ALL_CHECKS}


def test_mappings_are_well_formed():
    for check_id, mapping in load_mappings().items():
        assert mapping["title"] and mapping["why"], check_id
        assert mapping["category"] in ("security", "quality"), check_id
        assert set(mapping["owasp_llm_2026"]) <= OWASP_IDS, check_id
        assert set(mapping["nist_ai_rmf"]) <= NIST_FUNCTIONS, check_id
        assert all(ATLAS_ID.fullmatch(t) for t in mapping["atlas"]), check_id
        # A security finding must name an OWASP risk and an ATLAS technique;
        # a quality one has neither.
        is_security = mapping["category"] == "security"
        assert bool(mapping["owasp_llm_2026"]) == is_security, check_id
        assert bool(mapping["atlas"]) == is_security, check_id


def test_json_output_includes_mappings():
    result = CliRunner().invoke(app, ["scan", str(FIXTURES), "--json"])
    findings = [f for entry in json.loads(result.output) for f in entry["findings"]]
    by_check = {f["check_id"]: f["mapping"] for f in findings}
    assert by_check["prompt_injection_exposure"]["owasp_llm_2026"] == ["LLM01"]
    assert by_check["topic_overlap"]["category"] == "quality"
    assert by_check["prompt_injection_exposure"]["atlas"] == ["AML.T0051.001", "AML.T0053"]
