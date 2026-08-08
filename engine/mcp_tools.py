"""MCP tool-poisoning detection.

Public entrypoint: scan_mcp_tools(tools, judge_fn=None) -> McpScanResult

Scans MCP tool descriptions/metadata for hidden instructions before an agent
ever calls the tool (see engine/rules/jailbreak_phrases.yaml's tool_poisoning
section for the phrasing this targets). This is the same "hidden adversarial
instruction in text" problem engine.scan_text already solves for chat
messages -- just applied to tool metadata instead, so this module is a thin
per-tool wrapper around scan_text() rather than reimplementing detection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from engine.llm_judge import JudgeFn
from engine.scan_text import TextScanResult, scan_text


@dataclass(frozen=True)
class McpToolResult:
    name: str
    flagged: bool
    risk_score: float  # 0-100
    categories: list[str]
    reasons: list[str]
    owasp: dict
    scan: TextScanResult

    @property
    def layer1(self):
        return self.scan.layer1

    @property
    def layer3(self):
        return self.scan.layer3

    def to_dict(self) -> dict:
        d = self.scan.to_dict()
        d["name"] = self.name
        return d


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
    scan = scan_text(description, judge_fn=judge_fn)
    return McpToolResult(
        name=name,
        flagged=scan.flagged,
        risk_score=scan.risk_score,
        categories=scan.categories,
        reasons=scan.reasons,
        owasp=scan.owasp,
        scan=scan,
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
