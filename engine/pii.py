"""PII and secret detectors: email, phone, SSN, credit card (Luhn-validated), API keys.

Credit cards use a real Luhn checksum on top of the digit-count regex — a bare
"13-19 digit run" regex alone flags far too many false positives (order numbers,
tracking numbers, phone numbers, etc.).

These detectors are direction-agnostic (a leaked SSN is a leak whether it's in
the user's input or the model's output) and are run on both by
engine.layer1.run_layer1. `find_system_prompt_leak` below is the one detector
that's genuinely output-only -- it has nothing to compare against on the input
side, since a system prompt can only "leak" from an output.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# US-style phone numbers: (555) 123-4567, 555-123-4567, +1 555.123.4567, etc.
PHONE_RE = re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\d)")

# SSN-shaped: 123-45-6789. Deliberately excludes the invalid ranges the SSA
# never issues (000/666/900-999 area numbers) to cut obvious false positives.
SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")

# Broad candidate: any 13-19 digit run (allowing spaces/dashes as separators).
# Real digit-count-only detection stops here; Luhn validation below is what
# actually distinguishes a credit card number from a random long number.
CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")

# Extensible list of (name, regex) for common vendor API key formats.
API_KEY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai_api_key", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9]{20,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    # Not vendor-specific, but the same "secret material" bucket -- these are
    # the shapes most likely to leak in a model *output* (echoed from tool
    # results, retrieved docs, or training data) rather than typed by a user.
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("db_connection_string", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:@/]+:[^\s@/]+@[^\s/]+")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._-]{20,}\b")),
]


@dataclass(frozen=True)
class PIIMatch:
    kind: str  # e.g. "email", "phone", "ssn", "credit_card", "api_key:github_token"
    category: str  # "pii_leak" or "exfiltration" (for secrets/API keys)
    severity: str
    matched_text: str


def luhn_valid(digits: str) -> bool:
    """Standard Luhn mod-10 checksum used by all major card networks."""
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def find_emails(text: str) -> list[PIIMatch]:
    return [PIIMatch("email", "pii_leak", "medium", m.group(0)) for m in EMAIL_RE.finditer(text)]


def find_phones(text: str) -> list[PIIMatch]:
    return [PIIMatch("phone", "pii_leak", "low", m.group(0)) for m in PHONE_RE.finditer(text)]


def find_ssns(text: str) -> list[PIIMatch]:
    return [PIIMatch("ssn", "pii_leak", "high", m.group(0)) for m in SSN_RE.finditer(text)]


def find_credit_cards(text: str) -> list[PIIMatch]:
    matches = []
    for m in CC_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_valid(digits):
            matches.append(PIIMatch("credit_card", "pii_leak", "high", m.group(0)))
    return matches


def find_api_keys(text: str) -> list[PIIMatch]:
    matches = []
    for name, pattern in API_KEY_PATTERNS:
        for m in pattern.finditer(text):
            matches.append(PIIMatch(f"api_key:{name}", "exfiltration", "critical", m.group(0)))
    return matches


def find_system_prompt_leak(output_text: str, system_prompt: str, min_words: int = 6) -> PIIMatch | None:
    """Flag a model output that reproduces a long verbatim run of words from
    the application's own system prompt -- the output-side counterpart to the
    input-side "print your system prompt" heuristic rules.

    Uses difflib's longest-matching-block on word tokens rather than a
    substring/regex check, so paraphrased or reformatted leaks (extra
    whitespace, a word or two changed) still line up on the surrounding
    unchanged run of words.
    ponytail: word-level difflib, fine for typical system-prompt/response
    sizes (hundreds to low-thousands of words); switch to a rolling hash if
    this ever needs to scale to megabyte-sized transcripts.
    """
    if not output_text or not system_prompt:
        return None

    sys_words = system_prompt.split()
    out_words = output_text.split()
    matcher = difflib.SequenceMatcher(None, sys_words, out_words, autojunk=False)
    match = matcher.find_longest_match(0, len(sys_words), 0, len(out_words))
    if match.size < min_words:
        return None

    leaked = " ".join(out_words[match.b : match.b + match.size])
    return PIIMatch("system_prompt_leak", "exfiltration", "critical", leaked)


def scan_pii(text: str) -> list[PIIMatch]:
    """Run every PII/secret detector over text and return all matches found."""
    return [
        *find_emails(text),
        *find_phones(text),
        *find_ssns(text),
        *find_credit_cards(text),
        *find_api_keys(text),
    ]
