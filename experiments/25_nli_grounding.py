
import json
from collections import Counter
from pathlib import Path

import numpy as np
from sentence_transformers import CrossEncoder

from backend.grounding_validator import verify_grounding


ROOT = Path(__file__).resolve().parent.parent

POLICY_FILE = (
    ROOT / "data" / "knowledge_base"
    / "security_policies.json"
)

DATASET_FILE = (
    ROOT / "data" / "evaluations"
    / "unseen_adversarial_cases.json"
)

OUTPUT_FILE = (
    ROOT / "results"
    / "25_nli_grounding_results.json"
)

MODEL_NAME = "cross-encoder/nli-deberta-v3-small"

LABELS = [
    "contradiction",
    "entailment",
    "neutral",
]


def load_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def main():
    print("=== Experiment 25: NLI Grounding ===")

    policies = {
        doc["id"]: doc
        for doc in load_json(POLICY_FILE)
    }

    cases = load_json(DATASET_FILE)

    print(f"Loading NLI model: {MODEL_NAME}")

    model = CrossEncoder(
        MODEL_NAME,
        device="cpu",
        max_length=512,
    )

    pairs = []

    for case in cases:
        cited_id = case["cited_document"]

        if cited_id not in policies:
            raise ValueError(
                f"Unknown policy ID: {cited_id}"
            )

        policy = policies[cited_id]

        premise = (
            f"{policy['title']}. "
            f"{policy['content']}"
        )

        hypothesis = case["claim"]

        # NLI requires premise first, hypothesis second.
        pairs.append((premise, hypothesis))

    # Model returns logits for:
    # contradiction, entailment, neutral
    logits = model.predict(
        pairs,
        batch_size=4,
        show_progress_bar=True,
        apply_softmax=False,
        convert_to_numpy=True,
    )

    results = []

    for index, case in enumerate(cases):
        scores = np.asarray(
            logits[index],
            dtype=np.float64,
        )

        # Convert raw scores to probabilities.
        shifted = scores - scores.max()
        probabilities = np.exp(shifted)
        probabilities /= probabilities.sum()

        predicted_index = int(
            np.argmax(probabilities)
        )

        predicted_label = LABELS[predicted_index]

        confidence = float(
            probabilities[predicted_index]
        )

        probability_map = {
            label: round(float(probabilities[i]), 4)
            for i, label in enumerate(LABELS)
        }

        rule_result = verify_grounding(
            claim=case["claim"],
            cited_document=case["cited_document"],
        )

        expected = case["expected_result"]

        # Conservative mapping for exploratory comparison:
        # entailment -> supported
        # contradiction/neutral -> not verified
        #
        # This is NOT authorization to approve claims.
        nli_support_signal = (
            predicted_label == "entailment"
        )

        unsafe_support_signal = (
            expected == "unsupported"
            and nli_support_signal
        )

        result = {
            "test_id": case["test_id"],
            "attack_type": case["attack_type"],
            "claim": case["claim"],
            "cited_document": case["cited_document"],
            "expected_result": expected,
            "nli_prediction": predicted_label,
            "nli_confidence": round(confidence, 4),
            "nli_probabilities": probability_map,
            "nli_support_signal": nli_support_signal,
            "unsafe_support_signal": unsafe_support_signal,
            "rule_based_status": rule_result["status"],
        }

        results.append(result)

        print(f"\n{case['test_id']}")
        print(f"Expected: {expected}")
        print(f"NLI prediction: {predicted_label}")
        print(f"NLI confidence: {confidence:.4f}")
        print(f"Rule verdict: {rule_result['status']}")

        if unsafe_support_signal:
            print("WARNING: Unsafe NLI support signal!")

    total = len(results)

    unsafe_signals = sum(
        item["unsafe_support_signal"]
        for item in results
    )

    correct_support_signals = sum(
        item["expected_result"] == "supported"
        and item["nli_support_signal"]
        for item in results
    )

    summary = {
        "total_cases": total,
        "expected_supported": sum(
            case["expected_result"] == "supported"
            for case in results
        ),
        "expected_unsupported": sum(
            case["expected_result"] == "unsupported"
            for case in results
        ),
        "correct_support_signals": correct_support_signals,
        "unsafe_support_signals": unsafe_signals,
        "nli_predictions": dict(
            Counter(
                item["nli_prediction"]
                for item in results
            )
        ),
    }

    report = {
        "experiment": "25_nli_grounding",
        "model": MODEL_NAME,
        "method": (
            "NLI inference with full cited-policy text "
            "as premise and claim as hypothesis"
        ),
        "limitations": (
            "Predicted probabilities are not calibrated "
            "proof of factual support. NLI can misclassify "
            "domain-specific, compound, or long claims. "
            "Policy premises may be truncated at 512 tokens."
        ),
        "summary": summary,
        "results": results,
    }

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open(
        "w", encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False,
        )

    print("\n=== Experiment 25 Summary ===")

    for key, value in summary.items():
        print(f"{key}: {value}")

    print(f"Report saved: {OUTPUT_FILE}")
    print("\nExperiment 25 completed!")


if __name__ == "__main__":
    main()
