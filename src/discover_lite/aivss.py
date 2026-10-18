"""Risk scores from OWASP AIVSS v0.8, the AI Vulnerability Scoring System.

AIVSS scores one vulnerability in one agent, from 0.0 to 10.0:

    AARS  = (10 - CVSS_Base) * (Factor_Sum / 10) * ThM
    AIVSS = RoundHalfUp((CVSS_Base + AARS) * Mitigation_Factor, 1)

- CVSS_Base is the CVSS v4.0 base score of the vulnerability. Each check's
  vector is in mappings.yaml, and the `cvss` library computes the score.
- Factor_Sum adds ten agentic factors, each 0.0, 0.5 or 1.0 by the spec's
  rubric (Table 2). They describe the agent, so every finding in one agent
  shares them.
- ThM (threat multiplier) and Mitigation_Factor take the spec's defaults,
  0.97 and 1.0. A config file cannot show exploit maturity or validated
  mitigations, and the spec says to use the defaults unless shown otherwise.

A config cannot show every factor (memory, logging, identity changes, other
agents). Rather than guess, each score is a range: the low end counts only
what the config shows, the high end gives every unshown factor the worst
value, as the spec does for mitigation. Both ends are valid AIVSS scores; the
range closes as more of the agent becomes visible.

An agent's score is its highest finding's score. Quality findings have no
CVSS vector, because they are not vulnerabilities, so they are not scored.

Source: OWASP AIVSS, "Scoring System for OWASP Agentic AI Core Security
Risks" v0.8 (2026), sections 2.3 and 3.3 to 3.5.
"""

from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal

from cvss import CVSS4

from discover_lite.mappings import load_mappings
from discover_lite.models import Agent, Finding

THREAT_MULTIPLIER = Decimal("0.97")  # Spec default: proof of concept exists.
MITIGATION_FACTOR = Decimal("1.0")  # Spec default: no or weak mitigation.

# A factor the config does not show: 0.0 at the low end of the range and
# 1.0 (the worst case) at the high end.
ASSUMED = 1.0
NOT_SHOWN = "not shown in the config: 0.0 to 1.0"


@dataclass
class Factor:
    """One agentic factor's value and where it came from."""

    name: str
    value: float
    reason: str
    assumed: bool = False


@dataclass
class FindingScore:
    finding: Finding
    vector: str
    cvss_base: float
    aars: float
    score: float  # Unshown factors at their worst.
    low: float  # Only what the config shows.


@dataclass
class AgentRisk:
    """An agent's AIVSS range (None if no finding is scored) and how it was reached."""

    score: float | None  # High end: unshown factors at their worst.
    low: float | None  # Low end: only what the config shows.
    factors: list[Factor]
    findings: list[FindingScore]

    @property
    def text(self) -> str:
        """The range for display, e.g. "7.9-9.3 (High-Critical)"."""
        if not self.score:
            return "no security findings"
        if self.low == self.score:
            return f"{self.score} ({self.band})"
        bands = self.band if band(self.low) == self.band else f"{band(self.low)}-{self.band}"
        return f"{self.low}-{self.score} ({bands})"

    @property
    def band(self) -> str:
        return band(self.score)

    @property
    def factor_sum(self) -> float:
        return sum(f.value for f in self.factors)

    @property
    def shown_sum(self) -> float:
        return sum(f.value for f in self.factors if not f.assumed)


def band(score: float | None) -> str:
    """The spec's severity bands (section 3.5.2), the same as CVSS."""
    if not score:
        return "None"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def aivss(cvss_base: float, factor_sum: float) -> tuple[float, float]:
    """(AARS, AIVSS) for one vulnerability, by the spec's step-by-step procedure."""
    base = Decimal(str(cvss_base))
    aars = (10 - base) * (Decimal(str(factor_sum)) / 10) * THREAT_MULTIPLIER
    raw = (base + aars) * MITIGATION_FACTOR
    return float(aars), float(raw.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def factors(agent: Agent) -> list[Factor]:
    """The ten factors in the spec's order, each scored from the config where it can be."""
    actions = [t for t in agent.tools if t.capability in ("write", "execute")]
    unknown = [t for t in agent.tools if t.capability == "unknown"]
    runs_code = [t for t in agent.tools if t.capability == "execute"]
    unapproved = [t for t in actions + unknown if t.requires_approval is False]
    # MCP servers' tools are not in the config, so what they do is not shown.
    servers = bool(agent.servers)

    def assumed(name: str) -> Factor:
        return Factor(name, ASSUMED, NOT_SHOWN, assumed=True)

    # 1. Autonomy: can it act without a person signing off?
    if unapproved:
        autonomy = Factor("Autonomy", 1.0, f"{unapproved[0].name} runs without approval")
    elif not actions and not unknown and not servers:
        autonomy = Factor("Autonomy", 0.0, "no action tools")
    elif actions and not unknown and not servers and all(t.requires_approval for t in actions):
        autonomy = Factor("Autonomy", 0.0, "every action tool needs approval")
    else:
        autonomy = assumed("Autonomy")

    # 2. Tools: breadth and privilege of what it can call.
    if runs_code:
        tools = Factor("Tools", 1.0, f"{runs_code[0].name} runs code")
    elif servers or unknown:
        tools = assumed("Tools")
    elif actions:
        tools = Factor("Tools", 0.5, "read and write tools from a fixed list")
    else:
        tools = Factor("Tools", 0.0, "read-only tools or none")

    # 3. Language: does natural language drive actions?
    if actions or unknown or servers:
        language = Factor("Language", 1.0, "prompts drive tool calls")
    else:
        language = Factor("Language", 0.5, "prompts drive answers only, no action tools")

    # 4. Context: how much outside data drives decisions.
    if agent.untrusted_knowledge is True:
        context = Factor("Context", 1.0, "reads open content such as the web")
    elif agent.untrusted_knowledge is False:
        context = Factor("Context", 0.5, "reads only named, trusted sources")
    else:
        context = assumed("Context")

    # 5. Non-Determinism: an LLM varies; a guardrail bounds it.
    if agent.guardrail is True:
        variance = Factor("Non-Determinism", 0.5, "a guardrail bounds what it does")
    elif agent.guardrail is False:
        variance = Factor("Non-Determinism", 1.0, "LLM output with no guardrail")
    else:
        variance = assumed("Non-Determinism")

    # 10. Self-Mod: can it change its own code, prompts or tools?
    if runs_code:
        self_mod = Factor("Self-Mod", 1.0, f"{runs_code[0].name} can generate and run code")
    elif servers or unknown:
        self_mod = assumed("Self-Mod")
    else:
        self_mod = Factor("Self-Mod", 0.0, "fixed tool list, none runs code")

    # 6 to 9: logging, memory, identity and other agents are not in these configs.
    return [
        autonomy, tools, language, context, variance,
        assumed("Opacity"), assumed("Persistence"), assumed("Identity"), assumed("Multi-Agent"),
        self_mod,
    ]


def score_agent(agent: Agent, findings: list[Finding]) -> AgentRisk:
    """Score each security finding with AIVSS; the agent takes the highest."""
    agent_factors = factors(agent)
    factor_sum = sum(f.value for f in agent_factors)
    shown_sum = sum(f.value for f in agent_factors if not f.assumed)
    mappings = load_mappings()
    scored = []
    for finding in findings:
        vector = mappings[finding.check_id].get("cvss_v4", {}).get(finding.severity)
        if not vector:
            continue  # A quality finding: not a vulnerability.
        base = CVSS4(vector).base_score
        aars, score = aivss(float(base), factor_sum)
        scored.append(FindingScore(finding, vector, float(base), aars, score, aivss(float(base), shown_sum)[1]))
    scored.sort(key=lambda s: (s.score, s.low), reverse=True)
    return AgentRisk(
        max((s.score for s in scored), default=None),
        max((s.low for s in scored), default=None),
        agent_factors,
        scored,
    )
