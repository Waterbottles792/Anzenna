"""Tests for engine/owasp.py -- category -> OWASP LLM Top 10 ID mapping."""

from engine.owasp import owasp_ids_for, owasp_tags_for


def test_prompt_injection_maps_to_llm01():
    assert owasp_ids_for(["prompt_injection"]) == ["LLM01"]


def test_pii_leak_maps_to_llm02():
    assert owasp_ids_for(["pii_leak"]) == ["LLM02"]


def test_exfiltration_maps_to_llm01_and_llm07():
    assert owasp_ids_for(["exfiltration"]) == ["LLM01", "LLM07"]


def test_multiple_categories_deduped_and_sorted():
    ids = owasp_ids_for(["jailbreak", "prompt_injection", "pii_leak"])
    assert ids == ["LLM01", "LLM02"]


def test_unknown_category_contributes_nothing():
    assert owasp_ids_for(["totally_unknown"]) == []


def test_empty_categories_returns_empty_list():
    assert owasp_ids_for([]) == []


def test_owasp_tags_for_without_tool_poisoning_rule():
    tags = owasp_tags_for(["prompt_injection"], ["ignore_previous_instructions"])
    assert tags == {"owasp_llm": ["LLM01"]}


def test_owasp_tags_for_with_tool_poisoning_rule_adds_agentic_label():
    tags = owasp_tags_for(["prompt_injection"], ["tool_desc_hidden_instruction_tag"])
    assert tags["owasp_llm"] == ["LLM01"]
    assert tags["agentic_risk"] == ["agentic:tool_supply_chain_risk"]
