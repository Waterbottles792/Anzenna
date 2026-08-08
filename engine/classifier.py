"""ML classifier layer (Phase 2 of docs/plan.md).

Wraps a pretrained Hugging Face text-classification model behind the stable
`run_layer2(text) -> Layer2Result` interface described in
docs/contracts/DETECTION_INTERFACE.md, so the rest of the engine never needs
to know which model (or even which library) is doing the classifying.

Model choice: see CLASSIFIER_BENCHMARK.md.

Design notes:
- The real model is loaded lazily, on first call, and cached in a
  module-level dict keyed by model id -- NOT at import time (would make every
  test/tooling import slow by pulling in transformers/torch) and NOT
  per-request (would kill latency by reloading weights every call).
- The underlying model is swappable via the ANZENNA_CLASSIFIER_MODEL env var
  (any HF text-classification model id with a binary SAFE/INJECTION-style
  head). Callers of run_layer2() never need to change.
- The actual inference call is injectable via the `infer_fn` parameter so
  unit tests can mock it out entirely -- no network calls or model downloads
  in CI. `infer_fn` takes the raw text and returns a float in [0, 1]
  representing the probability the text is an injection/jailbreak attempt.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Optional

# ponytail: one config value (env var) naming the HF model id is enough here
# -- no model registry / plugin system needed for a single swappable model.
DEFAULT_MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"
MODEL_ID_ENV_VAR = "ANZENNA_CLASSIFIER_MODEL"

INJECTION_LABEL = "INJECTION"
SAFE_LABEL = "SAFE"

# score >= THRESHOLD maps to INJECTION_LABEL
THRESHOLD = 0.5

InferenceFn = Callable[[str], float]


@dataclass
class Layer2Result:
    score: float  # 0.0-1.0 probability the text is a prompt injection/jailbreak
    label: str  # INJECTION_LABEL or SAFE_LABEL


def _current_model_id() -> str:
    return os.environ.get(MODEL_ID_ENV_VAR, DEFAULT_MODEL_ID)


# module-level cache: model_id -> loaded InferenceFn. Populated lazily by
# _get_cached_infer_fn on first real (non-mocked) call.
_MODEL_CACHE: dict[str, InferenceFn] = {}


def _build_real_infer_fn(model_id: str) -> InferenceFn:
    """Load `model_id` via transformers and return a text -> score callable.

    Only imports transformers/torch here (not at module import time) so that
    importing engine.classifier -- and running the test suite, which always
    injects a mock infer_fn -- never requires those heavy deps or a network
    call to download weights.
    """
    from transformers import pipeline  # heavy import: kept lazy on purpose

    clf = pipeline(
        "text-classification",
        model=model_id,
        truncation=True,
        max_length=512,
    )

    def infer(text: str) -> float:
        result = clf(text)[0]
        label = str(result["label"]).upper()
        score = float(result["score"])
        # The pipeline returns the *predicted* class's label + score. Treat
        # any label containing "INJECTION" (or the generic LABEL_1 some
        # configs use) as the positive class; everything else is benign.
        if "INJECTION" in label or label in ("LABEL_1", "1"):
            return score
        return 1.0 - score

    return infer


def _get_cached_infer_fn(model_id: str) -> InferenceFn:
    if model_id not in _MODEL_CACHE:
        _MODEL_CACHE[model_id] = _build_real_infer_fn(model_id)
    return _MODEL_CACHE[model_id]


def run_layer2(text: str, infer_fn: Optional[InferenceFn] = None) -> Layer2Result:
    """Score `text` for prompt-injection/jailbreak likelihood.

    Args:
        text: the prompt or completion to classify.
        infer_fn: optional override, `text -> probability_of_injection`.
            Defaults to the real model (lazily loaded + cached on first
            call, keyed by the configured model id). Tests must always pass
            a mock here so they never touch the network or a real model.

    Returns:
        Layer2Result with a 0.0-1.0 score and an INJECTION/SAFE label.
    """
    fn = infer_fn if infer_fn is not None else _get_cached_infer_fn(_current_model_id())
    score = max(0.0, min(1.0, float(fn(text))))
    label = INJECTION_LABEL if score >= THRESHOLD else SAFE_LABEL
    return Layer2Result(score=score, label=label)
