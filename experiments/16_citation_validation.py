
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"

INPUT_FILE = RESULTS_DIR / "15_rag_comparison.json"
OUTPUT_FILE = RESULTS_DIR / "16_citation_validation.json"

POLICY_FILE = (
    ROOT / "data" / "knowledge_base"
    / "security_policies.json"
)


def extract_citations(answer):
    # Recognize both [POL-001] and POL-001
    return list(dict.fromkeys(
        match.group(0).upper()
        for match in re.finditer(
            r"\bPOL-\d{3}\b",
            answer,
            flags=re.IGNORECASE
        )
    ))


def validate_citations(
    answer,
    expected_source,
    retrieved_ids,
    known_ids
):
    citations = extract_citations(answer)

    unknown = [
        citation for citation in citations
        if citation not in known_ids
    ]

    not_retrieved = [
        citation for citation in citations
        if citation in known_ids
        and citation not in retrieved_ids
    ]

    wrong_source = [
        citation for citation in citations
        if citation != expected_source
        and citation in retrieved_ids
    ]

    if unknown or not_retrieved:
        status = "INVALID"
        reason = "Cites unavailable or unknown documents"

    elif not citations:
        status = "MISSING"
        reason = "No document IDs cited"

    elif expected_source not in citations:
        status = "MISMATCH"
        reason = "Expected supporting policy not cited"

    elif wrong_source:
        status = "REVIEW"
        reason = "Expected policy cited alongside other policies"

    else:
        status = "EXPECTED_SOURCE_FOUND"
        reason = "Expected document ID found in answer"

    return {
        "status": status,
        "reason": reason,
        "citations": citations,
        "expected_source": expected_source,
        "expected_source_present": expected_source in citations,
        "unknown_citations": unknown,
        "not_retrieved": not_retrieved,
        "other_citations": wrong_source
    }


def main():
    print("=== Experiment 16: Citation Validation ===")

    with INPUT_FILE.open("r", encoding="utf-8") as f:
        baseline = json.load(f)

    with POLICY_FILE.open("r", encoding="utf-8") as f:
        policies = json.load(f)

    known_ids = {policy["id"] for policy in policies}

    results = []

    for record in baseline["results"]:
        rag = record["with_rag"]

        evaluation = validate_citations(
            answer=rag["answer"],
            expected_source=record["expected_source"],
            retrieved_ids=rag["retrieved_document_ids"],
            known_ids=known_ids
        )

        results.append({
            "test_id": record["test_id"],
            "question": record["question"],
            "answer": rag["answer"],
            **evaluation
        })

        print(f"\n[{record['test_id']}] {evaluation['status']}")
        print(f"Expected: {record['expected_source']}")
        print(f"Detected citations: {evaluation['citations']}")
        print(f"Reason: {evaluation['reason']}")

    counts = Counter(
        record["status"] for record in results
    )

    report = {
        "experiment": "16_citation_validation",
        "source": INPUT_FILE.name,
        "method": "Deterministic document-ID validation",
        "limitations": (
            "Matching a citation to the expected document "
            "does not prove that the cited document "
            "supports every claim in the answer."
        ),
        "summary": {
            "total": len(results),
            "status_counts": dict(counts)
        },
        "results": results
    }

    with OUTPUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(
            report,
            f,
            indent=2,
            ensure_ascii=False
        )

    print("\n=== Citation Validation Summary ===")

    for status in [
        "EXPECTED_SOURCE_FOUND",
        "MISSING",
        "MISMATCH",
        "INVALID",
        "REVIEW"
    ]:
        print(f"{status}: {counts[status]}")

    print(f"Total evaluated: {len(results)}")
    print(f"Report saved: {OUTPUT_FILE}")
    print("\nExperiment 16 completed!")


if __name__ == "__main__":
    main()
