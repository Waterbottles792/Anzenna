"""Encoding-trick detection: base64 payload smuggling, zero-width/invisible
characters, homoglyph substitution, and unusual non-ASCII character density.

Base64 blobs are decoded and recursively re-scanned through the same
heuristics ruleset (engine.heuristics.match_text), since an attacker can
base64-wrap a jailbreak phrase to dodge a plain-text regex.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from engine.heuristics import match_text

# Minimum 20 chars (5 base64 groups of 4) before we bother trying to decode —
# shorter runs are too likely to be coincidental plain-English words. No
# trailing \b: a "=" padding char isn't a word char, so \b can't anchor
# after it — the character class itself is enough to bound the match.
BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

ZERO_WIDTH_CHARS = {"​", "‌", "‍", "⁠", "﻿"}

# A handful of common Cyrillic/Greek letters visually confusable with Latin
# ones — enough to catch typical homoglyph-substitution evasion attempts
# without pulling in a full Unicode confusables database.
HOMOGLYPH_CHARS = set("аеорсухАЕОРСУХ" "αορτυ" "ΑΒΕΖΗΙΚΜΝΟΡΤΥΧ")

MAX_DECODE_DEPTH = 3


@dataclass(frozen=True)
class EncodingFinding:
    kind: str
    category: str
    severity: str
    description: str
    detail: str


def find_base64_blobs(text: str) -> list[str]:
    return BASE64_RE.findall(text)


def try_decode_base64(candidate: str) -> str | None:
    """Decode candidate as base64 and return it only if it's valid printable UTF-8 text."""
    try:
        decoded_bytes = base64.b64decode(candidate, validate=True)
        decoded = decoded_bytes.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not decoded or not decoded.isprintable():
        return None
    return decoded


def _scan_base64(text: str, depth: int) -> list[EncodingFinding]:
    findings = []
    for candidate in find_base64_blobs(text):
        decoded = try_decode_base64(candidate)
        if decoded is None:
            continue

        sub_matches = match_text(decoded)
        if sub_matches:
            for hm in sub_matches:
                findings.append(
                    EncodingFinding(
                        kind=f"base64_decoded:{hm.rule_id}",
                        category=hm.category,
                        severity=hm.severity,
                        description=f"Base64-decoded content matched '{hm.rule_id}': {hm.description}",
                        detail=decoded[:200],
                    )
                )
        else:
            # Decodes cleanly to text but didn't trip a rule — still worth a
            # low-severity flag, since legitimate prompts rarely smuggle
            # base64-wrapped plain English.
            findings.append(
                EncodingFinding(
                    kind="base64_payload",
                    category="obfuscation",
                    severity="low",
                    description="Base64-encoded text payload found in input",
                    detail=decoded[:200],
                )
            )

        if depth < MAX_DECODE_DEPTH:
            findings.extend(_scan_base64(decoded, depth + 1))
    return findings


def find_zero_width_chars(text: str) -> list[EncodingFinding]:
    count = sum(1 for c in text if c in ZERO_WIDTH_CHARS)
    if count == 0:
        return []
    return [
        EncodingFinding(
            kind="zero_width_chars",
            category="obfuscation",
            severity="medium",
            description=f"{count} zero-width/invisible character(s) found (often used to split flagged words)",
            detail=repr(text[:200]),
        )
    ]


def find_homoglyphs(text: str) -> list[EncodingFinding]:
    count = sum(1 for c in text if c in HOMOGLYPH_CHARS)
    if count == 0:
        return []
    return [
        EncodingFinding(
            kind="homoglyphs",
            category="obfuscation",
            severity="medium",
            description=f"{count} homoglyph character(s) found (Cyrillic/Greek look-alikes of Latin letters)",
            detail=text[:200],
        )
    ]


def find_unusual_char_density(text: str, threshold: float = 0.3, min_len: int = 20) -> list[EncodingFinding]:
    """Flag text with an unusually high proportion of non-ASCII characters.

    A simple density check, not a language detector — fine for catching bulk
    obfuscation, not meant to flag ordinary non-English prose.
    """
    if len(text) < min_len:
        return []
    non_ascii = sum(1 for c in text if ord(c) > 127)
    ratio = non_ascii / len(text)
    if ratio <= threshold:
        return []
    return [
        EncodingFinding(
            kind="high_non_ascii_density",
            category="obfuscation",
            severity="low",
            description=f"Unusually high non-ASCII character density ({ratio:.0%})",
            detail=text[:200],
        )
    ]


def scan_encoding(text: str) -> list[EncodingFinding]:
    """Run all encoding-trick detectors over text."""
    return [
        *_scan_base64(text, depth=0),
        *find_zero_width_chars(text),
        *find_homoglyphs(text),
        *find_unusual_char_density(text),
    ]
