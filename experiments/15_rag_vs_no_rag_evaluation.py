
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx


ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"
RESULTS_DIR.mkdir(exist_ok=True)

OUTPUT_FILE = RESULTS_DIR / "15_rag_comparison.json"

API_URL = "http://127.0.0.1:8000"

# Expected facts come from our synthetic company policies.
TEST_CASES = [
    {
        "id": "EVAL-001",
        "question": (
            "What is the minimum corporate password length?"
        ),
        "expected_source": "POL-002",
        "required_terms": ["14"],
    },
    {
        "id": "EVAL-002",
        "question": (
            "What should I do after an unexpected "
            "MFA approval request?"
        ),
        "expected_source": "POL-001",
        "required_terms": ["report", "security"],
    },
    {
        "id": "EVAL-003",
        "question": (
            "What are the company's data "
            "classification levels?"
        ),
        "expected_source": "POL-004",
        "required_terms": [
            "public",
            "internal",
            "confidential",
            "restricted",
        ],
    },
    {
        "id": "EVAL-004",
        "question": (
            "What should employees use to access "
            "protected resources remotely?"
        ),
        "expected_source": "POL-005",
        "required_terms": ["vpn"],
    },
]


def normalize(text):
    text = text.lower().replace("-", " ")
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def evaluate_terms(answer, required_terms):
    normalized = normalize(answer)

    missing = [
        term for term in required_terms
        if normalize(term) not in normalized.split()
    ]

    return {
        "term_check_pass": len(missing) == 0,
        "missing_terms": missing,
    }


def query_api(client, endpoint, question):
    response = client.post(
        f"{API_URL}{endpoint}",
        json={"message": question},
    )

    response.raise_for_status()
    return response.json()


print("=== Experiment 15: RAG vs Non-RAG ===")

records = []

try:
    with httpx.Client(timeout=180.0) as client:

        for test in TEST_CASES:
            print(f"\n{'=' * 55}")
            print(f"Test: {test['id']}")
            print(f"Question: {test['question']}")

            # Query without retrieved documents
            baseline = query_api(
                client,
                "/chat",
                test["question"]
            )

            # Query with retrieved documents
            rag = query_api(
                client,
                "/chat/rag",
                test["question"]
            )

            baseline_check = evaluate_terms(
                baseline["response"],
                test["required_terms"]
            )

            rag_check = evaluate_terms(
                rag["response"],
                test["required_terms"]
            )

            sources = rag.get("sources", [])

            retrieved_ids = [
                source["document_id"]
                for source in sources
            ]

            # Extract generated source citations.
            cited_ids = re.findall(
                r"\[POL-\d{3}\]",
                rag["response"]
            )

            cited_ids = [
                citation.strip("[]")
                for citation in cited_ids
            ]

            expected_source_retrieved = (
                test["expected_source"] in retrieved_ids
            )

            expected_source_cited = (
                test["expected_source"] in cited_ids
            )

            invalid_citations = [
                citation for citation in cited_ids
                if citation not in retrieved_ids
            ]

            record = {
                "test_id": test["id"],
                "question": test["question"],
                "expected_source": test["expected_source"],
                "without_rag": {
                    "answer": baseline["response"],
                    "evaluation": baseline_check,
                    "generation_time_seconds": baseline.get(
                        "generation_time_seconds"
                    ),
                    "input_tokens": baseline.get("input_tokens"),
                    "generated_tokens": baseline.get(
                        "generated_tokens"
                    ),
                    "truncated": baseline.get("truncated"),
                },
                "with_rag": {
                    "answer": rag["response"],
                    "evaluation": rag_check,
                    "generation_time_seconds": rag.get(
                        "generation_time_seconds"
                    ),
                    "input_tokens": rag.get("input_tokens"),
                    "generated_tokens": rag.get(
                        "generated_tokens"
                    ),
                    "truncated": rag.get("truncated"),
                    "retrieved_document_ids": retrieved_ids,
                    "expected_source_retrieved": (
                        expected_source_retrieved
                    ),
                    "cited_document_ids": cited_ids,
                    "expected_source_cited": (
                        expected_source_cited
                    ),
                    "invalid_citations": invalid_citations,
                }
            }

            records.append(record)

            print("\n--- WITHOUT RAG ---")
            print(baseline["response"])
            print(
                "Term check:",
                baseline_check["term_check_pass"]
            )

            print("\n--- WITH RAG ---")
            print(rag["response"])
            print(
                "Term check:",
                rag_check["term_check_pass"]
            )
            print("Retrieved:", retrieved_ids)
            print(
                "Expected source retrieved:",
                expected_source_retrieved
            )
            print("Cited:", cited_ids)
            print(
                "Expected source cited:",
                expected_source_cited
            )

except (httpx.HTTPError, KeyError, ValueError) as error:
    print(f"\nEvaluation stopped: {error}")
    print("Check that FastAPI is running and responding.")
    raise SystemExit(1)


total = len(records)

baseline_passes = sum(
    record["without_rag"]["evaluation"]["term_check_pass"]
    for record in records
)

rag_passes = sum(
    record["with_rag"]["evaluation"]["term_check_pass"]
    for record in records
)

retrieval_passes = sum(
    record["with_rag"]["expected_source_retrieved"]
    for record in records
)

citation_passes = sum(
    record["with_rag"]["expected_source_cited"]
    for record in records
)

report = {
    "experiment": "15_rag_vs_no_rag_evaluation",
    "timestamp_utc": datetime.now(
        timezone.utc
    ).isoformat(),
    "model": "Qwen/Qwen3-0.6B",
    "method": "Single-run heuristic comparison",
    "limitations": (
        "Term checks do not prove factual accuracy. "
        "Citation labels do not prove claim support. "
        "Generation is stochastic and outcomes may vary."
    ),
    "summary": {
        "total_questions": total,
        "without_rag_term_passes": baseline_passes,
        "with_rag_term_passes": rag_passes,
        "expected_source_retrieved": retrieval_passes,
        "expected_source_cited": citation_passes,
    },
    "results": records,
}

with OUTPUT_FILE.open("w", encoding="utf-8") as file:
    json.dump(
        report,
        file,
        indent=2,
        ensure_ascii=False
    )

print("\n=== Final Evaluation Summary ===")
print(f"Questions evaluated: {total}")
print(f"Without RAG term checks: {baseline_passes}/{total}")
print(f"With RAG term checks: {rag_passes}/{total}")
print(f"Expected sources retrieved: {retrieval_passes}/{total}")
print(f"Expected sources cited: {citation_passes}/{total}")
print(f"Report saved: {OUTPUT_FILE}")

print("\nExperiment 15 completed!")
