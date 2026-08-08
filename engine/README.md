# engine/ — detection pipeline

This package implements the Anzenna detection pipeline (`docs/contracts/DETECTION_INTERFACE.md`).
Phase 1 (this doc's focus) builds the heuristics/regex layer:

- `rules/jailbreak_phrases.yaml` — the ruleset (pattern -> category -> severity)
- `heuristics.py` — loads the ruleset and matches text against it
- `pii.py` — email/phone/SSN/credit-card (Luhn-validated)/API-key detectors
- `encoding.py` — base64 decode+rescan, zero-width chars, homoglyphs, char density
- `layer1.py` — combines all of the above into `run_layer1(text) -> Layer1Result`
- `mcp_tools.py` — `scan_mcp_tools(tools) -> McpScanResult`: scans MCP tool
  descriptions/metadata for hidden instructions (tool-poisoning attacks) by
  running each description through Layer 1, escalating to Layer 3 (LLM judge)
  only when Layer 1 is ambiguous

## Adding a new rule

Open `engine/rules/jailbreak_phrases.yaml` and add an entry under `rules:`:

```yaml
  - id: my_new_rule               # unique slug, shows up in match output/tests
    category: jailbreak            # prompt_injection | jailbreak | exfiltration
    severity: high                 # low | medium | high | critical
    pattern: '\byour\s+regex\s+here\b'
    description: "Short human-readable reason surfaced in reasons/logs"
```

Notes:
- `pattern` is a Python `re` pattern, matched case-insensitively against the raw
  input text (`re.IGNORECASE`). Use `\b` word boundaries and keep patterns
  reasonably specific — broad patterns (e.g. matching the bare word "ignore")
  cause false positives on ordinary sentences.
- No code changes are needed — `engine/heuristics.py` loads and compiles every
  rule in the file at import time.
- Add both a true-positive and, if the phrase could plausibly appear in benign
  text, a false-positive test case to `engine/test_heuristics.py`.
- PII/secret detectors (email, phone, SSN, credit card, API keys) live in
  `engine/pii.py`, not the YAML file — add a new regex to `API_KEY_PATTERNS`
  there for a new vendor key format.

## Layer1Result shape

`run_layer1(text)` returns a `Layer1Result` with `triggered`, `categories`,
`matches`, `score` (0-100, this layer's contribution), and `reasons`. Its
`to_dict()` maps onto the `layer_results.heuristics` field described in
`docs/contracts/API_CONTRACT.md` — Phase 5 folds this (plus Layers 2/3) into
the final `ScanResult`.
