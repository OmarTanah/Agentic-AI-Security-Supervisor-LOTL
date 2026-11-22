"""Evaluate Layer 2 verdicts against the Semester 1 command dataset."""
import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT_PATH = Path(__file__).resolve().parents[1]
if str(ROOT_PATH) not in sys.path:
    sys.path.insert(0, str(ROOT_PATH))

from src.layer2.agent import run_agent


DATASET_PATH = ROOT_PATH / "tests" / "fixtures" / "evaluation_dataset.json"


def _metrics(results: list[tuple[str, str]]) -> dict[str, float | int]:
    """Calculate confusion-matrix counts and binary classification metrics."""
    true_positives = sum(actual == predicted == "malicious" for actual, predicted in results)
    true_negatives = sum(actual == predicted == "benign" for actual, predicted in results)
    false_positives = sum(actual == "benign" and predicted == "malicious" for actual, predicted in results)
    false_negatives = sum(actual == "malicious" and predicted == "benign" for actual, predicted in results)
    precision = true_positives / (true_positives + false_positives) if true_positives + false_positives else 0.0
    recall = true_positives / (true_positives + false_negatives) if true_positives + false_negatives else 0.0
    f1_score = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "TP": true_positives,
        "TN": true_negatives,
        "FP": false_positives,
        "FN": false_negatives,
        "Precision": precision,
        "Recall": recall,
        "F1-Score": f1_score,
    }


def evaluate(dataset_path: Path = DATASET_PATH, limit: int | None = None, delay: float = 5.0) -> dict[str, float | int]:
    """Run the agent over the dataset and print per-command and aggregate results."""
    with dataset_path.open(encoding="utf-8") as dataset_file:
        dataset: list[dict[str, str]] = json.load(dataset_file)
    entries = dataset[:limit] if limit is not None else dataset
    results: list[tuple[str, str]] = []

    for index, entry in enumerate(entries, start=1):
        event: dict[str, Any] = {
            "command_clean": entry["command"],
            "command_raw": entry["command"],
            "user": entry["user"],
            "host": "evaluation-host",
            "source": "auditd",
            "severity": "high" if entry["ground_truth"] == "malicious" else "low",
        }
        verdict = str(run_agent(event).get("verdict", "error"))
        results.append((entry["ground_truth"], verdict))
        status = "Correct" if verdict == entry["ground_truth"] else "Incorrect"
        print(f"[{index}/{len(entries)}] Processed: {entry['command']} -> Verdict: {verdict} ({status})")
        if index < len(entries):
            time.sleep(delay)

    metrics = _metrics(results)
    print("\nEvaluation Metrics:")
    for name in ("TP", "TN", "FP", "FN", "Precision", "Recall", "F1-Score"):
        print(f"{name}: {metrics[name]:.4f}" if isinstance(metrics[name], float) else f"{name}: {metrics[name]}")
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, help="Evaluate only the first N dataset entries")
    parser.add_argument("--delay", type=float, default=5.0, help="Seconds between API calls (default: 5)")
    args = parser.parse_args()
    evaluate(limit=args.limit, delay=args.delay)


if __name__ == "__main__":
    main()