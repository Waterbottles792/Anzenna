"""Evaluation harness for the Anzenna detection engine.

Scores a labeled dataset (engine/eval/dataset.jsonl) against any callable
matching `scan(text, direction, context=None) -> ScanResult` from
docs/contracts/DETECTION_INTERFACE.md. Deliberately layer-agnostic: it
never imports engine.pipeline/layer1/classifier/llm_judge directly, so it
works today (pointed at a dummy or single-layer function) and unchanged
once Phase 5's real scan() exists.

Library use:
    from engine.eval.run_eval import run_eval
    report = run_eval("engine/eval/dataset.jsonl", my_scan_fn)

CLI use:
    python -m engine.eval.run_eval --target engine.pipeline:scan
    python -m engine.eval.run_eval --target engine.layer1:run_layer1_as_scan
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ScanFn = Callable[..., Any]

DATASET_PATH = Path(__file__).parent / "dataset.jsonl"
RESULTS_DIR = Path(__file__).parent / "results"

LABELS = ("benign", "prompt_injection", "jailbreak", "pii_leak", "exfiltration")
ATTACK_LABELS = tuple(l for l in LABELS if l != "benign")


def load_dataset(path: str | Path = DATASET_PATH) -> list[dict]:
    """Load newline-delimited JSON examples, skipping blank lines."""
    rows = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{lineno}: invalid JSON - {e}") from e
            if row.get("label") not in LABELS:
                raise ValueError(f"{path}:{lineno}: unknown label {row.get('label')!r}")
            rows.append(row)
    return rows


def _field(result: Any, name: str, default: Any = None) -> Any:
    """Read a field off a ScanResult regardless of whether it's a dict,
    dataclass, or pydantic model -- the contract only fixes the shape."""
    if isinstance(result, dict):
        return result.get(name, default)
    return getattr(result, name, default)


def predicted_label(result: Any) -> str:
    """Collapse a ScanResult down to one label comparable to ground truth.

    verdict == "allow" -> benign. Otherwise the first recognized category
    on the result, or "unknown_attack" if it was flagged/blocked but
    didn't name a category we know about.
    """
    verdict = _field(result, "verdict", "allow")
    if verdict == "allow":
        return "benign"
    categories = _field(result, "categories", []) or []
    for cat in categories:
        if cat in ATTACK_LABELS:
            return cat
    return "unknown_attack"


@dataclass
class EvalReport:
    total: int
    errors: list[dict]
    confusion: dict[str, dict[str, int]]  # confusion[true_label][predicted_label] = count
    per_class: dict[str, dict[str, float]]
    binary: dict[str, float]
    accuracy: float

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "errors": self.errors,
            "confusion_matrix": self.confusion,
            "per_class": self.per_class,
            "binary_attack_vs_benign": self.binary,
            "accuracy": self.accuracy,
        }


def _prf1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def evaluate(dataset: list[dict], scan_fn: ScanFn) -> EvalReport:
    """Run every example through scan_fn and score the predictions.

    Examples where scan_fn raises are excluded from the metrics and
    reported separately in `errors` -- the target may be a
    work-in-progress layer, not the full pipeline.
    """
    all_labels = set(LABELS) | {"unknown_attack"}
    confusion: dict[str, dict[str, int]] = {t: defaultdict(int) for t in all_labels}
    errors: list[dict] = []
    scored = 0

    for row in dataset:
        true_label = row["label"]
        try:
            result = scan_fn(row["text"], row.get("direction", "input"), row.get("context"))
        except Exception as e:  # target under test may be incomplete/unstable
            errors.append({"text": row["text"][:120], "label": true_label, "error": repr(e)})
            continue
        pred = predicted_label(result)
        confusion[true_label][pred] += 1
        scored += 1

    per_class: dict[str, dict[str, float]] = {}
    for label in LABELS:
        tp = confusion[label].get(label, 0)
        fn = sum(v for k, v in confusion[label].items() if k != label)
        fp = sum(confusion[t].get(label, 0) for t in confusion if t != label)
        precision, recall, f1 = _prf1(tp, fp, fn)
        per_class[label] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": sum(confusion[label].values()),
        }

    # Binary attack-vs-benign -- the number that matters most for a
    # firewall: catch rate on attacks vs. false-positive rate on benign.
    tp = fp = fn = tn = 0
    for true_label, preds in confusion.items():
        true_is_attack = true_label != "benign"
        for pred_label, count in preds.items():
            pred_is_attack = pred_label != "benign"
            if true_is_attack and pred_is_attack:
                tp += count
            elif true_is_attack and not pred_is_attack:
                fn += count
            elif not true_is_attack and pred_is_attack:
                fp += count
            else:
                tn += count
    b_precision, b_recall, b_f1 = _prf1(tp, fp, fn)
    binary = {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(b_precision, 4),
        "recall": round(b_recall, 4),
        "f1": round(b_f1, 4),
        "accuracy": round((tp + tn) / scored, 4) if scored else 0.0,
    }

    accuracy = sum(confusion[l].get(l, 0) for l in LABELS) / scored if scored else 0.0
    confusion_plain = {t: dict(v) for t, v in confusion.items()}

    return EvalReport(
        total=scored,
        errors=errors,
        confusion=confusion_plain,
        per_class=per_class,
        binary=binary,
        accuracy=round(accuracy, 4),
    )


def run_eval(
    dataset_path: str | Path = DATASET_PATH,
    scan_fn: ScanFn | None = None,
    save_results: bool = False,
    results_dir: str | Path = RESULTS_DIR,
) -> dict:
    """Library entrypoint: load the dataset, score it against scan_fn,
    optionally persist a timestamped result file, return the report dict.
    """
    if scan_fn is None:
        raise ValueError("scan_fn is required")
    dataset = load_dataset(dataset_path)
    report = evaluate(dataset, scan_fn).to_dict()
    if save_results:
        results_dir = Path(results_dir)
        results_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = results_dir / f"{stamp}.json"
        out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        report["_saved_to"] = str(out_path)
    return report


def _load_target(dotted: str) -> ScanFn:
    """Resolve 'module.path:function_name' into a callable."""
    if ":" not in dotted:
        raise ValueError("--target must be 'module.path:function_name'")
    module_path, func_name = dotted.split(":", 1)
    module = importlib.import_module(module_path)
    fn = getattr(module, func_name)
    if not callable(fn):
        raise ValueError(f"{dotted} is not callable")
    return fn


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score the eval dataset against a scan() target.")
    parser.add_argument("--target", required=True, help="dotted path, e.g. engine.pipeline:scan")
    parser.add_argument("--dataset", default=str(DATASET_PATH), help="path to a dataset.jsonl")
    parser.add_argument("--no-save", action="store_true", help="don't write a timestamped result file")
    args = parser.parse_args(argv)

    scan_fn = _load_target(args.target)
    report = run_eval(args.dataset, scan_fn, save_results=not args.no_save)
    print(json.dumps(report, indent=2))
    if report["errors"]:
        print(
            f"\n{len(report['errors'])} example(s) raised an exception in scan_fn -- see 'errors'.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
