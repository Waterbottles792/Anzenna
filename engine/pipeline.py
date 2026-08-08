"""Phase 5 -- Unified Pipeline + Scoring.

Public entrypoint: scan(text, direction, context=None) -> ScanResult

This is the ONE function docs/contracts/DETECTION_INTERFACE.md promises the
API layer (Phase 7): stable signature, zero web/DB dependencies, callable
directly in a unit test. See engine/SCORING.md for the scoring formula and
the cost-control (layer-skipping) rules this module implements.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

from engine.classifier import INJECTION_LABEL, InferenceFn, run_layer2
from engine.layer1 import run_layer1
from engine.llm_judge import JudgeFn, run_layer3
from engine.owasp import owasp_tags_for

# Defaults chosen in engine/SCORING.md's baseline-eval tuning pass; override
# per call via the `thresholds` param (e.g. a stricter customer config).
DEFAULT_THRESHOLDS = {"block": 80.0, "flag": 35.0}


@dataclass(frozen=True)
class ScanResult:
    """Matches docs/contracts/API_CONTRACT.md's POST /v1/scan response shape,
    minus `latency_ms` (the API layer's job to add), plus an `owasp` field
    (OWASP LLM Top 10 IDs -- see engine/owasp.py; not in the original
    contract, but every other engine result object already carries it)."""

    verdict: str  # "allow" | "flag" | "block"
    risk_score: float  # 0-100
    categories: list[str]
    reasons: list[str]
    owasp: dict
    layer_results: dict

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "categories": self.categories,
            "reasons": self.reasons,
            "owasp": self.owasp,
            "layer_results": self.layer_results,
        }


def scan(
    text: str,
    direction: str = "input",
    context: Optional[dict] = None,
    *,
    judge_fn: Optional[JudgeFn] = None,
    classifier_infer_fn: Optional[InferenceFn] = None,
    thresholds: Optional[dict] = None,
) -> ScanResult:
    """Run the full detection pipeline over `text`.

    - Layer 1 (heuristics/PII/encoding) always runs -- cheap, deterministic.
    - Layer 2 (ML classifier) runs unless Layer 1 alone already crossed the
      block threshold (already decided; no need for a second opinion). If
      the classifier itself is unavailable (e.g. `transformers`/`torch` not
      installed -- see pyproject.toml's optional `ml` extra), that's treated
      like Layer 3's judge_unavailable: skip its contribution, note it in
      `reasons`, never crash the scan.
    - Layer 3 (LLM judge) only runs if the Layer 1 + Layer 2 combined score
      lands in the ambiguous band between `flag` and `block` thresholds --
      not confidently benign, not confidently an attack either.
    """
    t = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    block_threshold = float(t["block"])
    flag_threshold = float(t["flag"])

    layer1 = run_layer1(text, direction=direction, context=context)
    categories = set(layer1.categories)
    reasons = list(layer1.reasons)
    risk_score = layer1.score

    layer2_result = None
    if layer1.score < block_threshold:
        try:
            layer2_result = run_layer2(text, infer_fn=classifier_infer_fn)
        except Exception as exc:  # noqa: BLE001 - classifier_unavailable, never crash the scan
            reasons.append(f"classifier_unavailable: {exc}")
        else:
            risk_score = max(risk_score, layer2_result.score * 100.0)
            if layer2_result.label == INJECTION_LABEL:
                categories.add("prompt_injection")
                reasons.append(f"ML classifier flagged likely injection (score={layer2_result.score:.2f})")

    layer3_result = None
    if flag_threshold <= risk_score < block_threshold:
        layer3_result = run_layer3(text, context=context, judge_fn=judge_fn)
        if layer3_result.available and layer3_result.triggered:
            risk_score = max(risk_score, layer3_result.score * 100.0)
            reasons.append(f"llm_judge: {layer3_result.reasoning}")
            categories.add("prompt_injection")
        elif not layer3_result.available:
            reasons.append(layer3_result.reasoning)  # already prefixed "judge_unavailable: ..."

    risk_score = min(100.0, risk_score)
    if risk_score >= block_threshold:
        verdict = "block"
    elif risk_score >= flag_threshold:
        verdict = "flag"
    else:
        verdict = "allow"

    sorted_categories = sorted(categories)
    match_ids = [m.id for m in layer1.matches if m.source == "heuristics"]

    return ScanResult(
        verdict=verdict,
        risk_score=risk_score,
        categories=sorted_categories,
        reasons=reasons,
        owasp=owasp_tags_for(sorted_categories, match_ids),
        layer_results={
            "heuristics": layer1.to_dict(),
            "classifier": asdict(layer2_result) if layer2_result is not None else None,
            "llm_judge": asdict(layer3_result) if layer3_result is not None else None,
        },
    )
