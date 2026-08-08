"""OWASP category mapping.

Maps every flagged detection category onto OWASP LLM Top 10 (2025) IDs
(https://genai.owasp.org/llm-top-10/), so a scan result can be handed to an
auditor as a citation instead of raw text.

OWASP's Agentic AI taxonomy (covering things like MCP tool poisoning) is much
newer and its ID numbering isn't stable/verifiable enough yet to hardcode a
specific "ASIxx" id here without risking a wrong citation -- findings that
come from the tool-poisoning ruleset (engine/mcp_tools.py) instead get a
plain-language `agentic_risk` label. Swap in real IDs once OWASP finalizes
that numbering.
"""

from __future__ import annotations

CATEGORY_TO_OWASP: dict[str, list[str]] = {
    "prompt_injection": ["LLM01"],  # Prompt Injection
    "jailbreak": ["LLM01"],  # Prompt Injection (jailbreak sub-type)
    "exfiltration": ["LLM01", "LLM07"],  # Prompt Injection -> System Prompt Leakage
    "pii_leak": ["LLM02"],  # Sensitive Information Disclosure
    "obfuscation": ["LLM01"],  # Prompt Injection (encoding-based evasion)
}

# Rule ids from the tool-poisoning ruleset (see engine/rules/jailbreak_phrases.yaml)
# all share this prefix -- used to add the agentic-risk label on top of the
# base OWASP LLM category.
_AGENTIC_RULE_PREFIX = "tool_desc_"
AGENTIC_TOOL_POISONING_TAG = "agentic:tool_supply_chain_risk"


def owasp_ids_for(categories: list[str]) -> list[str]:
    """Map flagged categories to OWASP LLM Top 10 IDs, deduped and sorted."""
    ids: set[str] = set()
    for category in categories:
        ids.update(CATEGORY_TO_OWASP.get(category, []))
    return sorted(ids)


def owasp_tags_for(categories: list[str], match_ids: list[str]) -> dict:
    """Full compliance-tag dict for a result: OWASP LLM Top 10 IDs, plus an
    agentic_risk label if any matched rule id came from the tool-poisoning
    ruleset."""
    tags: dict = {"owasp_llm": owasp_ids_for(categories)}
    if any(mid.startswith(_AGENTIC_RULE_PREFIX) for mid in match_ids):
        tags["agentic_risk"] = [AGENTIC_TOOL_POISONING_TAG]
    return tags
