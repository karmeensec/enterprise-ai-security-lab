
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    ROOT / "results"
    / "26_hybrid_grounding_results.json"
)

OUTPUT_FILE = (
    ROOT / "results"
    / "27_hybrid_policy_comparison.json"
)


def conservative_policy(case):
    """Reuse the original Experiment 26 decision."""
    return case["predicted"]


def contradiction_aware_policy(case):
    """
    Keep original support rules.

    Allow a clear rejection when both rule and NLI
    indicate contradiction.
    """
    rule = case["rule_status"]
    probabilities = case["nli"]["probabilities"]

    if (
        rule == "unsupported"
        and probabilities["contradiction"] >= 0.80
    ):
        return "unsupported"

    return conservative_policy(case)


def balanced_policy(case):
    """
    Experimental policy:
    - Approval requires rule-based support plus
      NLI entailment with probability >= 0.50.
    - Rejection requires rule-based unsupported
      plus strong NLI contradiction.
    - Otherwise abstain.
    """
    rule = case["rule_status"]
    probabilities = case["nli"]["probabilities"]

    if (
        rule == "supported"
        and case["nli"]["label"] == "entailment"
        and probabilities["entailment"] >= 0.50
    ):
        return "supported"

    if (
        rule == "unsupported"
        and probabilities["contradiction"] >= 0.80
    ):
        return "unsupported"

    return "needs_review"


POLICIES = {
    "conservative_baseline": conservative_policy,
    "contradiction_aware": contradiction_aware_policy,
    "balanced_experimental": balanced_policy,
}


def calculate_metrics(cases):
    total = len(cases)

    exact = sum(
        case["expected"] == case["predicted"]
        for case in cases
    )

    unsupported = [
        case for case in cases
        if case["expected"] == "unsupported"
    ]

    supported = [
        case for case in cases
        if case["expected"] == "supported"
    ]

    unsafe = [
        case for case in unsupported
        if case["predicted"] == "supported"
    ]

    false_rejections = [
        case for case in supported
        if case["predicted"] == "unsupported"
    ]

    abstentions = [
        case for case in cases
        if case["predicted"] == "needs_review"
    ]

    supported_approved = sum(
        case["predicted"] == "supported"
        for case in supported
    )

    unsupported_rejected = sum(
        case["predicted"] == "unsupported"
        for case in unsupported
    )

    return {
        "total": total,
        "exact_matches": exact,
        "exact_match_rate": round(exact / total, 4),
        "unsafe_approvals": len(unsafe),
        "false_rejections": len(false_rejections),
        "supported_approved": supported_approved,
        "unsupported_rejected": unsupported_rejected,
        "abstentions": len(abstentions),
        "abstention_rate": round(
            len(abstentions) / total, 4
        ),
    }


def main():
    print("=== Experiment 27: Decision Policy Comparison ===")

    with INPUT_FILE.open("r", encoding="utf-8") as file:
        experiment_26 = json.load(file)

    baseline_cases = experiment_26["results"]

    report = {
        "experiment": "27_hybrid_policy_comparison",
        "source": INPUT_FILE.name,
        "limitations": (
            "These decision policies are evaluated on "
            "previously used, development-influenced cases. "
            "NLI probabilities are not calibrated safety "
            "guarantees. Policies must be tested on new "
            "held-out cases before deployment."
        ),
        "policies": {},
    }

    for policy_name, policy_function in POLICIES.items():
        evaluated = []

        for original in baseline_cases:
            predicted = policy_function(original)

            evaluated.append({
                "test_id": original["test_id"],
                "dataset": original["dataset"],
                "expected": original["expected"],
                "predicted": predicted,
                "rule_status": original["rule_status"],
                "nli": original["nli"],
            })

        metrics = calculate_metrics(evaluated)

        report["policies"][policy_name] = {
            "metrics": metrics,
            "results": evaluated,
        }

        print(f"\n--- {policy_name} ---")
        print(
            f"Exact matches: "
            f"{metrics['exact_matches']}/{metrics['total']}"
        )
        print(
            f"Unsafe approvals: "
            f"{metrics['unsafe_approvals']}"
        )
        print(
            f"False rejections: "
            f"{metrics['false_rejections']}"
        )
        print(
            f"Supported approved: "
            f"{metrics['supported_approved']}"
        )
        print(
            f"Unsupported rejected: "
            f"{metrics['unsupported_rejected']}"
        )
        print(
            f"Needs review: "
            f"{metrics['abstentions']}"
        )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False,
        )

    print("\nExperiment 27 completed!")
    print(f"Report saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
