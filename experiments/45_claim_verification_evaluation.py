
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from backend.claim_verification import verify_answer_claims


ROOT = Path(__file__).resolve().parent.parent

INPUT = ROOT / "results" / "43_rag_attack_results.json"

OUTPUT = (
    ROOT / "results" / "45_claim_verification_evaluation.json"
)

KNOWN_IDS = [
    "POL-001",
    "POL-002",
    "POL-003",
    "POL-004",
    "POL-005",
]


def main():
    if not INPUT.is_file():
        raise FileNotFoundError(
            f"Missing Experiment 43 report: {INPUT}"
        )

    report = json.loads(
        INPUT.read_text(encoding="utf-8")
    )

    results = []

    print("=" * 65)
    print("EXPERIMENT 45 - CLAIM-LEVEL VERIFICATION")
    print("=" * 65)

    for case in report["results"]:
        case_id = case["id"]

        if not isinstance(case.get("model_response"), str):
            raise ValueError(
                f"Missing model response for {case_id}"
            )

        # Experiment 43 used one synthetic
        # policy reference: POL-005.
        assessment = verify_answer_claims(
            answer=case["model_response"],
            retrieved_document_ids=["POL-005"],
            known_document_ids=KNOWN_IDS,
        )

        claim_statuses = [
            item["status"]
            for item in assessment["claims"]
        ]

        record = {
            "case_id": case_id,
            "category": case["category"],
            "original_response": case["model_response"],
            "decision": assessment["decision"],
            "reason": assessment["reason"],
            "claim_count": len(assessment["claims"]),
            "claim_assessments": assessment["claims"],
            "citation_status": assessment[
                "citation_validation"
            ]["status"],
            "safe_to_release_automatically": assessment[
                "safe_to_release_automatically"
            ],
        }

        results.append(record)

        print()
        print("Case:", case_id)
        print("Decision:", record["decision"])
        print("Reason:", record["reason"])
        print("Citation status:", record["citation_status"])
        print("Claim count:", record["claim_count"])
        print("Claim statuses:", claim_statuses)

        for index, claim in enumerate(
            record["claim_assessments"], start=1
        ):
            print(
                f"  Claim {index}: "
                f"{claim['status']} - {claim['claim']}"
            )

    counts = Counter(
        item["decision"]
        for item in results
    )

    false_releases = [
        item["case_id"]
        for item in results
        if item["safe_to_release_automatically"]
    ]

    output = {
        "experiment": "45_claim_verification_evaluation",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "evaluation_mode": "offline_saved_qwen_responses",
        "summary": {
            "cases": len(results),
            "blocked": counts["blocked"],
            "review_required": counts["review_required"],
            "automatic_release_flags": false_releases,
        },
        "results": results,
        "limitations": [
            "Rule-based grounding only.",
            "No new model inference.",
            "Synthetic policy dataset.",
            "Sentence splitting is heuristic.",
            "Citations are attributed per sentence.",
            "Missing citations do not automatically prove an attack.",
            "No automatic release of generated answers.",
        ],
    }

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT.write_text(
        json.dumps(output, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print()
    print("=" * 65)
    print("CLAIM VERIFICATION SUMMARY")
    print("=" * 65)
    print("Cases evaluated:", len(results))
    print("Blocked:", counts["blocked"])
    print("Review required:", counts["review_required"])
    print("Automatic release flags:", false_releases)
    print("Report saved:", OUTPUT)


if __name__ == "__main__":
    main()
