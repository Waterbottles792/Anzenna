"""MCP tool-poisoning detection.

Public entrypoint: scan_mcp_tools(tools, judge_fn=None) -> McpScanResult

Scans MCP tool descriptions/metadata for hidden instructions before an agent
ever calls the tool (see engine/rules/jailbreak_phrases.yaml's tool_poisoning
section for the phrasing this targets). This is the same "hidden adversarial
instruction in text" problem run_layer1/run_layer3 already solve for chat
messages -- just applied to tool metadata instead, so this module wires those
two layers together rather than reimplementing detection.

Layer 3 (LLM judge) only runs when Layer 1 is ambiguous (triggered but not
already high-confidence), mirroring the cost-control approach docs/plan.md
describes for the eventual Phase 5 pipeline.
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
class McpToolResult:
    name: str
    flagged: bool
    risk_score: float  # 0-100
    categories: list[str]
    reasons: list[str]
    owasp: dict
    layer1: Layer1Result
    layer3: Optional[Layer3Result]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
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


@dataclass(frozen=True)
class McpScanResult:
    triggered: bool
    flagged_tools: list[str]
    tools: list[McpToolResult]

    def to_dict(self) -> dict:
        return {
            "triggered": self.triggered,
            "flagged_tools": self.flagged_tools,
            "tools": [t.to_dict() for t in self.tools],
        }


def _scan_one_tool(name: str, description: str, judge_fn: Optional[JudgeFn]) -> McpToolResult:
    layer1 = run_layer1(description)

    layer3: Optional[Layer3Result] = None
    if layer1.triggered and layer1.score < LAYER1_CONFIDENT_THRESHOLD:
        layer3 = run_layer3(description, judge_fn=judge_fn)

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

    return McpToolResult(
        name=name,
        flagged=risk_score >= FLAG_THRESHOLD,
        risk_score=min(100.0, risk_score),
        categories=sorted_categories,
        reasons=reasons,
        owasp=owasp_tags_for(sorted_categories, match_ids),
        layer1=layer1,
        layer3=layer3,
    )


def scan_mcp_tools(tools: list[dict], judge_fn: Optional[JudgeFn] = None) -> McpScanResult:
    """Scan a list of MCP tool definitions for hidden/malicious instructions
    in their descriptions before an agent ever calls them.

    Each entry in `tools` is a dict with at least a "description" key (the
    real MCP tool-list shape also has "name" and "inputSchema"; only
    "description" -- the field attackers actually hide instructions in -- is
    scanned). "name" defaults to its index if missing.
    """
    results = [
        _scan_one_tool(str(t.get("name", i)), t.get("description", ""), judge_fn)
        for i, t in enumerate(tools)
    ]
    flagged = [r.name for r in results if r.flagged]
    return McpScanResult(triggered=bool(flagged), flagged_tools=flagged, tools=results)
