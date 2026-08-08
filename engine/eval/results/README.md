# Eval results

Each run of `run_eval.py` against a real target writes one timestamped
JSON file here, e.g.:

```
20260115T093000Z.json
```

The filename is the UTC timestamp of the run (`%Y%m%dT%H%M%SZ`). Contents
are the full report dict from `run_eval()`: overall + per-category
precision/recall/F1, the confusion matrix, and any examples that raised
an exception in the target.

Never overwrite or edit a result file after the fact — commit a new one.
Keeping one file per run makes it possible to `git diff` / `git log -p`
across runs to see whether a tuning change to the heuristics, classifier,
or LLM judge actually helped or hurt, and it's a useful record of
progress over time.

This directory is empty right now because there's nothing to run the
harness against yet (Phase 5's unified `scan()` doesn't exist). Once a
target is available:

```
make eval TARGET=engine.pipeline:scan
```

or directly:

```
python -m engine.eval.run_eval --target engine.pipeline:scan
```
