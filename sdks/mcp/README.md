# sdks/mcp — Anzenna MCP server

Exposes the Anzenna detection engine as MCP tools, so any MCP-aware host
(Claude Desktop, Claude Code, etc.) can add scanning with one config block
and zero application code.

## Tools

- **`scan(text, direction="input", system_prompt=None)`** — scans text for
  prompt injection, jailbreak attempts, and PII/secret leaks. Pass
  `direction="output"` plus the app's `system_prompt` when scanning a model
  response, to also catch the response leaking that system prompt verbatim.
- **`scan_tool_descriptions(tools)`** — scans a list of MCP tool definitions
  (`{"name": ..., "description": ...}`) for hidden instructions (tool-poisoning
  attacks) before an agent trusts/calls them. Point this at another MCP
  server's tool list before wiring it into your agent.

Both return `risk_score` (0-100), `flagged`, `categories`, human-readable
`reasons`, and OWASP LLM Top 10 IDs.

## Install & config

Requires the `mcp` extra: `pip install -e ".[mcp]"` from the repo root.

Add to your MCP host's config (e.g. `claude_desktop_config.json` or `.mcp.json`):

```json
{
  "mcpServers": {
    "anzenna": {
      "command": "python",
      "args": ["-m", "sdks.mcp.server"],
      "cwd": "/absolute/path/to/anzenna"
    }
  }
}
```

## Run directly

```bash
python -m sdks.mcp.server
```

Speaks MCP over stdio. `GEMINI_API_KEY` must be set (see `.env.example`) for
the LLM-judge escalation path (`engine/llm_judge.py`) to actually call out;
without it, ambiguous matches still get flagged on Layer 1's score alone,
just without the judge's second opinion.

## Note on packaging

This isn't published to PyPI yet -- Phase 10 in `docs/plan.md` covers the
Python/Node SDKs' actual packaging, at which point this would ship the same
way (e.g. an `anzenna-mcp` console script instead of `python -m ...`).
