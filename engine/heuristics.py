"""Ruleset-driven regex matcher for jailbreak / prompt-injection / exfiltration phrases.

Rules live in engine/rules/jailbreak_phrases.yaml (pattern -> category -> severity),
not hardcoded here, so the ruleset can be edited without touching code. See
engine/README.md for how to add a rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

RULES_PATH = Path(__file__).parent / "rules" / "jailbreak_phrases.yaml"

SEVERITY_WEIGHTS = {
    "low": 15,
    "medium": 35,
    "high": 60,
    "critical": 90,
}


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    pattern: re.Pattern
    description: str


@dataclass(frozen=True)
class HeuristicMatch:
    rule_id: str
    category: str
    severity: str
    description: str
    matched_text: str


@lru_cache(maxsize=1)
def load_rules(path: Path = RULES_PATH) -> tuple[Rule, ...]:
    """Load and compile rules from the YAML ruleset. Cached — file is read once per process."""
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    rules = []
    for entry in raw.get("rules", []):
        rules.append(
            Rule(
                id=entry["id"],
                category=entry["category"],
                severity=entry["severity"],
                pattern=re.compile(entry["pattern"], re.IGNORECASE),
                description=entry["description"],
            )
        )
    return tuple(rules)


def match_text(text: str, rules: tuple[Rule, ...] | None = None) -> list[HeuristicMatch]:
    """Scan text against every rule, returning one HeuristicMatch per rule that fires.

    A linear scan over the ruleset is enough at this rule count (dozens, not
    thousands) — no need for a compiled trie/priority engine.
    """
    if rules is None:
        rules = load_rules()

    matches = []
    for rule in rules:
        m = rule.pattern.search(text)
        if m:
            matches.append(
                HeuristicMatch(
                    rule_id=rule.id,
                    category=rule.category,
                    severity=rule.severity,
                    description=rule.description,
                    matched_text=m.group(0),
                )
            )
    return matches
