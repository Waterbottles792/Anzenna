"""Anzenna MCP server.

Exposes the detection engine (engine/) as MCP tools, so any MCP-aware host
(Claude Desktop, Claude Code, etc.) can add Anzenna scanning with one config
block and zero application code -- see README.md in this directory.

The business logic (`scan`, `scan_tool_descriptions`) is plain, undecorated
functions so it's testable without the MCP transport; `build_server()`
registers them on an mcp.server.mcpserver.MCPServer instance. The `mcp`
package is only imported inside `build_server()`/`main()` (lazy) so importing
this module for its functions/tests never requires it installed.
"""

from __future__ import annotations

from typing import Optional

from engine.mcp_tools import scan_mcp_tools
from engine.scan_text import scan_text


def scan(text: str, direction: str = "input", system_prompt: Optional[str] = None) -> dict:
    """Scan text for prompt injection, jailbreak attempts, PII/secret leaks,
    and (when direction="output") verbatim system-prompt leakage. Returns
    risk_score (0-100), flagged categories, human-readable reasons, and
    OWASP LLM Top 10 IDs. Pass direction="output" and the app's system_prompt
    when scanning a model response, to also catch the response leaking it."""
    context = {"system_prompt": system_prompt} if system_prompt else None
    return scan_text(text, direction=direction, context=context).to_dict()


def scan_tool_descriptions(tools: list[dict]) -> dict:
    """Scan a list of MCP tool definitions (each a dict with "name" and
    "description") for hidden instructions -- MCP tool-poisoning attacks --
    before trusting/calling them. Use this on any MCP server's tool list you
    don't fully control before wiring it into an agent."""
    return scan_mcp_tools(tools).to_dict()


def build_server():
    from mcp.server.mcpserver import MCPServer  # heavy/optional: only needed to actually serve

    server = MCPServer("anzenna")
    server.tool(name="scan", description=scan.__doc__)(scan)
    server.tool(name="scan_tool_descriptions", description=scan_tool_descriptions.__doc__)(scan_tool_descriptions)
    return server


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
