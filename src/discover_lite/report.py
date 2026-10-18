"""Scan a config file or a folder and build the one-page HTML report.

`scan_path` is shared with the CLI, so the report and `discover-lite scan`
always agree. The page is rendered from a Jinja2 template with autoescaping
on: evidence comes from config files we do not control, so any HTML in it
must be shown as text, never run.
"""

import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from discover_lite import stats
from discover_lite.checks import run_all
from discover_lite.connectors import load_agents
from discover_lite.coverage import cell, coverage
from discover_lite.mappings import load_mappings
from discover_lite.models import Agent, Finding
from discover_lite.scoring import WEIGHTS, score_agent
from discover_lite.verifier import load_policy, policy_path, verify

TEMPLATES = Path(__file__).parent / "templates"

# Used to list the most serious findings first.
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# How each check reads in the estate summary, after "N of M agents".
SUMMARY_PHRASES = {
    "secret_in_config": "have a secret written into their config",
    "unpinned_package": "run a package with no exact version",
    "insecure_remote_server": "reach a remote server over plain HTTP or without an Authorization header",
    "missing_scope": "have instructions too short to limit what they do",
    "no_human_in_loop": "have a tool that changes data with no approval",
    "open_access": "are open to anyone or to the whole organisation",
    "unclassified_tool": "have a tool we could not classify, running without approval",
    "prompt_injection_exposure": "read untrusted content and can also take actions",
    "topic_overlap": "have topics whose trigger phrases overlap",
    "broad_filesystem_access": "give a filesystem server a whole disk or home folder",
    "no_guardrail": "have no guardrail screening inputs and outputs",
}


@dataclass
class ScannedAgent:
    agent: Agent
    findings: list[Finding]
    score: float
    breakdown: dict[str, float]


def config_files(path: Path) -> list[Path]:
    """The file itself, or every .json file under a folder."""
    return [path] if path.is_file() else sorted(path.rglob("*.json"))


def default_policies(path: Path) -> Path:
    """Where policy files sit by default: `policies/` beside a file, or inside a folder."""
    return (path.parent if path.is_file() else path) / "policies"


def scan_path(target: Path) -> list[ScannedAgent]:
    """Run every check on every agent in one config file, or in every .json file under a folder."""
    results = []
    for path in config_files(target):
        # Files we do not recognise give no agents and are skipped.
        for agent in load_agents(path):
            findings = sorted(run_all(agent), key=lambda f: SEVERITY_ORDER[f.severity])
            score, breakdown = score_agent(findings)
            results.append(ScannedAgent(agent, findings, score, breakdown))
    return results


def top_issues(results: list[ScannedAgent], n: int = 3) -> list[str]:
    """The checks failed by the most agents, as plain sentences."""
    affected = {}
    for r in results:
        for check in {f.check_id for f in r.findings}:
            affected[check] = affected.get(check, 0) + 1
    # Most agents first; ties go to the heavier issue, then by name.
    ranked = sorted(affected, key=lambda c: (-affected[c], -WEIGHTS[c], c))
    return [f"{affected[c]} of {len(results)} agents {SUMMARY_PHRASES[c]}." for c in ranked[:n]]


def _fetch_date(folder: Path) -> str:
    """The most recent date in the folder's FETCHED.md, or "" if none."""
    record = folder / "FETCHED.md"
    dates = re.findall(r"\d{4}-\d{2}-\d{2}", record.read_text()) if record.exists() else []
    return max(dates, default="")


def real_world_sections(github_dir: Path | None, registry_dir: Path | None) -> list[dict]:
    """Aggregate statistics from downloaded public data, if it is there.

    Counts and percentages only: no file names, repository names or values.
    """
    sections = []
    if github_dir is not None and github_dir.is_dir():
        agents, skipped = stats.collect(github_dir)
        sections.append({
            "title": "Public MCP client configs on GitHub",
            "fetched": _fetch_date(github_dir),
            "rows": stats.compute(agents, skipped),
            "checks": stats.findings_by_check(agents),
        })
    if registry_dir is not None and registry_dir.is_dir():
        agents, _ = stats.collect(registry_dir)
        sections.append({
            "title": "Official MCP Registry",
            "fetched": _fetch_date(registry_dir),
            "rows": stats.registry_rows(agents),
            "checks": [],
        })
    return sections


def build_report(
    target: Path,
    policies_dir: Path | None = None,
    github_dir: Path | None = None,
    registry_dir: Path | None = None,
) -> str:
    """The full report for a config file or a folder, as one self-contained HTML page."""
    results = scan_path(target)
    all_findings = [f for r in results for f in r.findings]

    verifications = []
    if policies_dir is not None and policies_dir.is_dir():
        for r in results:
            path = policy_path(policies_dir, r.agent)
            if path.exists():
                verifications.append((r.agent, verify(r.agent, load_policy(path))))

    table = coverage([r.agent for r in results])
    coverage_rows = [
        (label, [cell(*table[p][label]) for p in table]) for label in next(iter(table.values()), {})
    ]

    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html"]))
    return env.get_template("report.html").render(
        today=date.today().isoformat(),
        target=str(target),
        results=sorted(results, key=lambda r: -r.score),
        agents_with_findings=sum(bool(r.findings) for r in results),
        counts={s: sum(f.severity == s for f in all_findings) for s in SEVERITY_ORDER},
        total_findings=len(all_findings),
        top_issues=top_issues(results),
        mappings=load_mappings(),
        verifications=verifications,
        platforms=list(table),
        coverage_rows=coverage_rows,
        real_world=real_world_sections(github_dir, registry_dir),
    )
