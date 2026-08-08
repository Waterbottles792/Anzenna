"""Layer 1 + Layer 3 text scan with cost-controlled escalation.

Public entrypoint: scan_text(text, direction="input", context=None, judge_fn=None) -> TextScanResult

Not the full Phase 5 scan() from docs/contracts/DETECTION_INTERFACE.md (no
verdict/threshold config, no Layer 2 classifier, no eval baseline) -- just
the two layers cheap/safe enough to combine on their own: Layer 1
(deterministic) always runs, Layer 3 (LLM judge) only runs when Layer 1 is
ambiguous (triggered but not already high-confidence).

This escalation logic originally lived only in engine.mcp_tools (scanning
tool descriptions instead of messages); it's pulled out here so mcp_tools
and any other caller (e.g. an MCP server exposing a generic scan tool) share
one implementation instead of drifting copies of the same thresholds.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

from engine.layer1 import Layer1Result, run_layer1
from engine.llm_judge import JudgeFn, Layer3Result, run_layer3
from engine.owasp import owasp_tags_for

# ponytail: one fixed cutoff, not a tunable scoring engine -- Phase 5 owns the
# real cross-layer scoring formula once it exists (see docs/plan.md Phase 5).
FLAG_THRESHOLD = 50.0
# Layer 1 scores at/above this are already confident; skip the LLM judge call.
LAYER1_CONFIDENT_THRESHOLD = 75.0


@dataclass(frozen=True)
class TextScanResult:
    flagged: bool
    risk_score: float  # 0-100
    categories: list[str]
    reasons: list[str]
    owasp: dict
    layer1: Layer1Result
    layer3: Optional[Layer3Result]

    def to_dict(self) -> dict:
        return {
            "flagged": self.flagged,
            "risk_score": self.risk_score,
            "categories": self.categories,
            "reasons": self.reasons,
            "owasp": self.owasp,
            "layer_results": {
                "heuristics": self.layer1.to_dict(),
                "llm_judge": asdict(self.layer3) if self.layer3 is not None else None,
            },
        }


def scan_text(
    text: str,
    direction: str = "input",
    context: Optional[dict] = None,
    judge_fn: Optional[JudgeFn] = None,
) -> TextScanResult:
    """Run Layer 1 over `text`, escalating to Layer 3 only when Layer 1 is
    ambiguous. `direction`/`context` are passed through to run_layer1 (so
    direction="output" + context={"system_prompt": ...} also runs the
    system-prompt-leak check) and to run_layer3 (system_prompt helps the
    judge reason about context)."""
    layer1 = run_layer1(text, direction=direction, context=context)

    layer3: Optional[Layer3Result] = None
    if layer1.triggered and layer1.score < LAYER1_CONFIDENT_THRESHOLD:
        layer3 = run_layer3(text, context=context, judge_fn=judge_fn)

    risk_score = layer1.score
    categories = list(layer1.categories)
    reasons = list(layer1.reasons)
    if layer3 is not None and layer3.available and layer3.triggered:
        risk_score = max(risk_score, layer3.score * 100.0)
        reasons.append(f"llm_judge: {layer3.reasoning}")
        if "prompt_injection" not in categories:
            categories.append("prompt_injection")

    sorted_categories = sorted(categories)
    match_ids = [m.id for m in layer1.matches if m.source == "heuristics"]

    return TextScanResult(
        flagged=risk_score >= FLAG_THRESHOLD,
        risk_score=min(100.0, risk_score),
        categories=sorted_categories,
        reasons=reasons,
        owasp=owasp_tags_for(sorted_categories, match_ids),
        layer1=layer1,
        layer3=layer3,
    )
