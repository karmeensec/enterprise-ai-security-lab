
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"

INPUT_FILES = [
    RESULTS / "18_grounding_results.json",
    RESULTS / "19_adversarial_grounding.json",
    RESULTS / "21_unseen_adversarial_results.json",
]

OUTPUT_FILE = RESULTS / "23_security_metrics.json"


def main():
    all_cases = []

    for path in INPUT_FILES:
        with path.open("r", encoding="utf-8") as file:
            report = json.load(file)

        for case in report["results"]:
            all_cases.append({
                "dataset": path.name,
                "test_id": case["test_id"],
                "expected": case["expected"],
                "predicted": case["predicted"],
            })

    total = len(all_cases)

    exact_matches = sum(
        case["expected"] == case["predicted"]
        for case in all_cases
    )

    unsupported_cases = [
        case for case in all_cases
        if case["expected"] == "unsupported"
    ]

    supported_cases = [
        case for case in all_cases
        if case["expected"] == "supported"
    ]

    unsafe_approvals = [
        case for case in unsupported_cases
        if case["predicted"] == "supported"
    ]

    supported_rejections = [
        case for case in supported_cases
        if case["predicted"] == "unsupported"
    ]

    abstentions = [
        case for case in all_cases
        if case["predicted"] == "needs_review"
    ]

    safe_handling = [
        case for case in unsupported_cases
        if case["predicted"] in (
            "unsupported",
            "needs_review"
        )
    ]

    summary = {
        "total_cases": total,
        "exact_matches": exact_matches,
        "exact_match_rate": round(
            exact_matches / total, 4
        ),
        "unsupported_cases": len(unsupported_cases),
        "unsafe_approvals": len(unsafe_approvals),
        "unsafe_approval_rate": round(
            len(unsafe_approvals) / len(unsupported_cases),
            4
        ) if unsupported_cases else None,
        "safe_handling_of_unsupported": len(safe_handling),
        "supported_cases": len(supported_cases),
        "supported_rejections": len(supported_rejections),
        "abstentions": len(abstentions),
        "abstention_rate": round(
            len(abstentions) / total, 4
        ),
    }

    report = {
        "experiment": "23_security_evaluation_metrics",
        "method": "Deterministic multi-dataset evaluation",
        "limitations": (
            "Results apply only to predefined test cases. "
            "Abstention is safer than false approval but "
            "does not establish factual correctness."
        ),
        "summary": summary,
        "cases": all_cases,
    }

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print("=== Experiment 23: Security Metrics ===")

    for name, value in summary.items():
        print(f"{name}: {value}")

    print(f"\nReport saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
