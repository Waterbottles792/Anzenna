"""Layer 1: combined heuristics + PII + encoding-trick detection.

Public entrypoint: run_layer1(text) -> Layer1Result.

This is the cheap, deterministic, no-network-calls layer that always runs
first in the eventual Phase 5 pipeline (see docs/plan.md "Phase 5 — Unified
Pipeline + Scoring"). This module does not do that wiring — it only needs to
return a shape that's easy to fold into the `layer_results.heuristics` field
of the ScanResult described in docs/contracts/API_CONTRACT.md /
DETECTION_INTERFACE.md.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from engine.encoding import scan_encoding
from engine.heuristics import SEVERITY_WEIGHTS, match_text
from engine.pii import scan_pii


@dataclass(frozen=True)
class Layer1Match:
    source: str  # "heuristics" | "pii" | "encoding"
    id: str  # rule id (heuristics) or detector kind (pii/encoding)
    category: str  # "prompt_injection" | "jailbreak" | "exfiltration" | "pii_leak" | "obfuscation"
    severity: str  # "low" | "medium" | "high" | "critical"
    description: str
    matched_text: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Layer1Result:
    """Result of run_layer1(). Maps directly onto API_CONTRACT.md's
    `layer_results.heuristics = { "triggered": bool, "matches": [...] }`,
    with `categories`/`score`/`reasons` available for Phase 5 to fold into
    the top-level `categories`, `risk_score`, and `reasons` fields.
    """

    triggered: bool
    categories: list[str]
    matches: list[Layer1Match]
    score: float  # 0-100, this layer's own contribution to the final risk_score
    reasons: list[str]

    def to_dict(self) -> dict:
        return {
            "triggered": self.triggered,
            "categories": self.categories,
            "matches": [m.to_dict() for m in self.matches],
            "score": self.score,
            "reasons": self.reasons,
        }


def run_layer1(text: str) -> Layer1Result:
    """Run every Layer 1 detector (regex rules, PII/secrets, encoding tricks) over text.

    Score is a simple sum of each match's severity weight, capped at 100.
    That's intentionally simple: this is one layer's preliminary contribution,
    not the final cross-layer score — Phase 5 owns the real scoring formula.
    """
    matches: list[Layer1Match] = []

    for hm in match_text(text):
        matches.append(
            Layer1Match("heuristics", hm.rule_id, hm.category, hm.severity, hm.description, hm.matched_text)
        )

    for pm in scan_pii(text):
        matches.append(
            Layer1Match("pii", pm.kind, pm.category, pm.severity, f"Detected {pm.kind}", pm.matched_text)
        )

    for ef in scan_encoding(text):
        matches.append(
            Layer1Match("encoding", ef.kind, ef.category, ef.severity, ef.description, ef.detail)
        )

    categories = sorted({m.category for m in matches})
    score = min(100.0, float(sum(SEVERITY_WEIGHTS[m.severity] for m in matches)))
    reasons = [f"{m.description} ({m.category}/{m.severity})" for m in matches]

    return Layer1Result(
        triggered=bool(matches),
        categories=categories,
        matches=matches,
        score=score,
        reasons=reasons,
    )
