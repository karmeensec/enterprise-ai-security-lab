
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from backend.grounding_decision_policy import (
    decide_grounding_action,
)
from backend.grounding_validator import load_policies


ROOT = Path(__file__).resolve().parent.parent

INPUT = (
    ROOT / "results" / "44_hybrid_grounding_evaluation.json"
)

OUTPUT = (
    ROOT / "results" / "44_grounding_decision_evaluation.json"
)

EXPECTED_ACTIONS = {
    "GR-001": "release_candidate",
    "GR-002": "block",
    "GR-003": "block",
    "GR-004": "block",
    "GR-005": "release_candidate",
    "GR-006": "review_required",
    "GR-007": "review_required",
    "GR-008": "block",
    "GR-009": "review_required",
    "GR-010": "block",
}


def main():
    report = json.loads(
        INPUT.read_text(encoding="utf-8")
    )

    known_ids = set(load_policies().keys())
    results = []

    print("=" * 65)
    print("EXPERIMENT 44 - GROUNDING DECISION EVALUATION")
    print("=" * 65)

    for case in report["results"]:
        case_id = case["id"]
        document_id = case["cited_document"]

        # This is an isolated decision-policy evaluation.
        # We simulate verified retrieval for known IDs.
        # No actual retrieval occurs in this experiment.
        citation_check_simulated = document_id in known_ids

        decision = decide_grounding_action(
            rule_status=case["rule_prediction"],
            hybrid_status=case["hybrid_prediction"],
            citations_verified=citation_check_simulated,
            injection_detected=False,
        )

        actual = decision["action"]
        expected = EXPECTED_ACTIONS[case_id]

        record = {
            "id": case_id,
            "expected_claim_status": case["expected"],
            "rule_status": case["rule_prediction"],
            "hybrid_status": case["hybrid_prediction"],
            "simulated_citation_check": citation_check_simulated,
            "expected_action": expected,
            "actual_action": actual,
            "reason": decision["reason"],
            "matches_expectation": actual == expected,
            "false_release_candidate": (
                actual == "release_candidate"
                and case["expected"] != "supported"
            ),
        }

        results.append(record)

        print(
            f"{case_id}: "
            f"rule={record['rule_status']}, "
            f"hybrid={record['hybrid_status']}, "
            f"action={actual}, "
            f"match={record['matches_expectation']}"
        )

    counts = Counter(
        record["actual_action"]
        for record in results
    )

    mismatches = [
        record["id"]
        for record in results
        if not record["matches_expectation"]
    ]

    false_candidates = [
        record["id"]
        for record in results
        if record["false_release_candidate"]
    ]

    output = {
        "experiment": "44_grounding_decision_evaluation",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "evaluation_mode": "offline_saved_results",
        "summary": {
            "total_cases": len(results),
            "block": counts["block"],
            "review_required": counts["review_required"],
            "release_candidate": counts["release_candidate"],
            "expectation_mismatches": mismatches,
            "false_release_candidates": false_candidates,
        },
        "limitations": [
            "Retrieval verification is simulated.",
            "No live RAG endpoint was called.",
            "Claims were evaluated individually.",
            "Release candidates are not authorized "
            "for automatic user-facing release.",
            "The test cases were used to design "
            "the decision policy.",
        ],
        "results": results,
    }

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT.write_text(
        json.dumps(output, indent=2),
        encoding="utf-8",
    )

    print()
    print("=" * 65)
    print("DECISION EVALUATION SUMMARY")
    print("=" * 65)
    print("Total cases:", len(results))
    print("Blocked:", counts["block"])
    print("Review required:", counts["review_required"])
    print("Release candidates:", counts["release_candidate"])
    print("Expectation mismatches:", mismatches)
    print("False release candidates:", false_candidates)
    print("Report saved:", OUTPUT)


if __name__ == "__main__":
    main()
