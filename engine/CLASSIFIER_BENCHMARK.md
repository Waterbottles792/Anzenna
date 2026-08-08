# Classifier Layer (Phase 2) — Model Choice & Latency

## Model picked

**`protectai/deberta-v3-base-prompt-injection-v2`** (Hugging Face, Apache 2.0)

- Fine-tuned `microsoft/deberta-v3-base` (~184M params), binary head:
  `0 -> SAFE`, `1 -> INJECTION`.
- Reported eval on 20k held-out prompts: 95.25% accuracy, 91.59% precision,
  99.74% recall, 95.49% F1.
- No paid API, no GPU requirement — runs fine on CPU (see latency below),
  weights fit comfortably in memory on a small instance.
- It's the most widely deployed open-source prompt-injection classifier
  (used in ProtectAI's own `llm-guard` scanner, referenced as the baseline
  example in Lakera's public `pint-benchmark` repo), so it has more
  real-world scrutiny and published numbers than newer/smaller
  alternatives.

Caveat worth flagging: the `llm-guard` project that packages this model
has slowed down in commit activity, and the model card itself notes it
doesn't detect jailbreak-style attacks (only injection) and isn't meant to
scan system prompts. Since it sits behind `run_layer2()` with the model id
swappable via `ANZENNA_CLASSIFIER_MODEL`, upgrading to a newer model later
(e.g. `protectai/deberta-v3-small-prompt-injection-v2` for a smaller
footprint, or a jailbreak-specific model) needs no caller changes — this
is the ML layer, jailbreak-phrase coverage also lives in `engine/heuristics.py`.

Alternatives considered:
- `deberta-v3-small-prompt-injection-v2` — same family, ~100M params,
  slightly lower accuracy (94.28%), smaller/faster. Good fallback if CPU
  latency becomes a bottleneck; swap via the env var, no code changes.
- `deepset/deberta-v3-base-injection` — similar size class, less commonly
  cited in comparative benchmarks.
- Anything Llama-Guard-scale or larger was ruled out per Phase 2 scope —
  multi-GB weights and meaningfully worse CPU latency for a service that
  needs to score every request inline.

## Latency (as published, not independently re-run)

From ProtectAI's own `llm-guard` benchmark docs for this exact model
(`docs/input_scanners/prompt_injection.md`, 384-token inputs, 5-run
average):

| Hardware                | Standard (PyTorch) | With ONNX export |
|--------------------------|--------------------|-------------------|
| CPU — AWS `m5.xlarge`    | ~213 ms/request (~1,804 QPS aggregate) | ~104 ms/request (~3,685 QPS aggregate) |
| GPU — AWS `g5.xlarge`    | ~81 ms/request (~4,740 QPS aggregate)  | ~7.6 ms/request (~50,217 QPS aggregate) |

Separate community benchmarks of DeBERTa-v3-base-scale classifiers report
figures as low as ~15 ms/request on a laptop CPU and ~3 ms/request on GPU
for shorter inputs — actual latency is dominated by input token length and
whether ONNX/quantization is used, not just model choice.

## Hosting implication (for Phase 12)

- CPU-only hosting is viable for moderate request volume, especially with
  the ONNX export (~2x speedup shown above). No GPU is required to ship.
- If per-request latency budget gets tight (this layer runs inline in
  `scan()` alongside heuristics + optionally the LLM judge), the cheapest
  lever is exporting to ONNX before reaching for GPU instances — GPU only
  pays off at higher sustained QPS.
- The small variant (`deberta-v3-small-prompt-injection-v2`) is a one-line
  env var swap (`ANZENNA_CLASSIFIER_MODEL`) if base-model CPU latency ever
  becomes the bottleneck.

## Running real inference locally

The test suite never imports `transformers`/`torch` or downloads weights —
`run_layer2()`'s inference call is injectable and tests always pass a mock.
To actually run the real model, install the optional `ml` dependency group
(`pip install -e ".[ml]"`) and call `run_layer2("some text")` with no
`infer_fn` override; the model downloads and loads once, lazily, on first
call.
