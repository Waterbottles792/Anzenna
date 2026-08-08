# Scoring — how `scan()` computes `risk_score` and `verdict`

Implemented in `engine/pipeline.py`. This is Phase 5's formula per
`docs/plan.md`; the individual layers (1-4) don't own scoring, `scan()` does.

## The formula: max, not a weighted sum

```
risk_score = max(
    layer1.score,              # 0-100, engine/layer1.py's own severity-weighted sum
    layer2.score * 100,        # if Layer 2 ran
    layer3.score * 100,        # if Layer 3 ran AND triggered
)
```

**Why max and not a weighted average:** the three layers aren't peers voting
on the same question -- they're independent nets with different failure
modes, and each one is capable of being *right on its own*:

- Layer 1 (regex) is precise but narrow: a `critical`-severity match (a
  literal "you are now DAN" or "print your system prompt") is about as
  certain as detection gets. Averaging that down with a classifier that
  happens to score the same text lower would only ever make the system
  *less* safe, never more accurate -- regex false positives are rare by
  construction (patterns are hand-written to be specific; see
  `engine/README.md`'s "keep patterns reasonably specific" guidance).
- Layer 2 (ML classifier) exists specifically to catch paraphrased/novel
  attacks Layer 1's fixed patterns miss. If it's confident and Layer 1 saw
  nothing, that confidence must not get diluted by averaging against a 0.
- Layer 3 (LLM judge) is the most expensive and, by construction, only ever
  consulted when the other two disagree or are unsure. When it *does* fire,
  it's meant to be closer to a tie-breaker than a co-equal vote.

A weighted average lets any single layer's true positive get dragged down by
the others' silence. `max` means **any one layer being confident is enough**
-- consistent with `engine/scan_text.py`'s existing Layer1+Layer3 combination
(this formula is that same pattern, extended to include Layer 2).

Layer 3's score is only folded in when `triggered` is true (mirrors
`engine/scan_text.py`); an available-but-not-triggered judge result
contributes nothing, since "the judge looked and found nothing" isn't a
signal that should raise the score.

## Cost-control: which layers run

| Layer | Runs when |
|---|---|
| 1 (heuristics/PII/encoding) | Always. No network calls, no ML model. |
| 2 (ML classifier) | `layer1.score < block_threshold` -- skipped only when Layer 1 *alone* already crossed the block line; a second opinion can't change a decision that's already made. |
| 3 (LLM judge) | `flag_threshold <= risk_score < block_threshold` after Layers 1+2 -- the literal "ambiguous band" between "flag" and "block": not confidently benign, not confidently an attack either. |

This reuses the two verdict thresholds themselves as the escalation
boundaries, rather than inventing separate magic cutoffs -- the band where
Layer 3 is worth its cost is by definition the band where the verdict is
still undecided.

## Verdict thresholds

```python
DEFAULT_THRESHOLDS = {"block": 80.0, "flag": 40.0}
```

- `risk_score >= block` -> `"block"`
- `flag <= risk_score < block` -> `"flag"`
- `risk_score < flag` -> `"allow"`

Configurable per call via `scan(..., thresholds={"block": ..., "flag": ...})`
(Phase 7's job to expose this as a per-customer config).

### Where the defaults came from

`block=80` was picked, not tuned: below a single `critical` heuristic match
(90, so an unambiguous attack always blocks on Layer 1 alone) and above two
stacked `medium` matches (70, so one medium-confidence signal doesn't
auto-block). No eval sweep changed it -- the dataset didn't have enough
high-score borderline cases near 80 to move it.

`flag=35` **was** tuned against a real run of `engine/eval/dataset.jsonl`
(185 examples) through the actual `scan()`, via a threshold sweep (see
below). Starting point was 40 (just above one `medium` match, 35); the
sweep showed 35 itself was strictly better and nothing below 35 changed the
result further, so 35 (exactly `SEVERITY_WEIGHTS["medium"]`) is the real
floor, not an arbitrary pick.

| flag threshold | precision | recall | f1 | false positives |
|---|---|---|---|---|
| 40 (before) | 0.902 | 0.308 | 0.460 | 4 |
| **35 (after, default)** | **0.915** | **0.358** | **0.515** | 4 |
| 30 down to 1 | 0.915 | 0.358 | 0.515 | 4 | *(no further change)* |

Recall stays low in absolute terms (0.358) -- expected, and not a threshold
problem. See the caveat below.

**Caveat on this baseline eval** (`engine/eval/results/`): the recorded run
used Layer 1 live, but **Layer 2 was unavailable** (`transformers`/`torch`
aren't installed by default -- see pyproject.toml's `ml` extra) and **Layer
3 calls failed** (`GEMINI_API_KEY` in `.env` is returning 401 Unauthorized).
`scan()` degrades both gracefully (see `pipeline.py`'s
`classifier_unavailable`/`judge_unavailable` handling) rather than crashing,
so the run completed, but its numbers reflect **Layer 1 (regex/PII/encoding)
alone**, not the full 3-layer pipeline -- e.g. the `exfiltration` category's
0.0 recall in this run means Layer 1's ruleset doesn't cover most of that
category's phrasing, not that the pipeline can't detect it; Layers 2/3 exist
specifically to catch what Layer 1 misses. Layer 2's own standalone accuracy
is documented separately in `engine/CLASSIFIER_BENCHMARK.md` (95%+ on its
own eval set). Re-run `make eval TARGET=engine.pipeline:scan` after
installing `.[ml]` and fixing the Gemini key to get a true 3-layer baseline,
and re-tune both thresholds against those numbers -- expect `flag` and
possibly `block` to move once Layers 2/3 are contributing real signal.
