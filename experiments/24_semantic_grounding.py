
import json
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer

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
    / "24_semantic_grounding_results.json"
)

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


def load_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def main():
    print("=== Experiment 24: Semantic Grounding ===")

    policies = {
        doc["id"]: doc
        for doc in load_json(POLICY_FILE)
    }

    cases = load_json(DATASET_FILE)

    print(f"Loading embedding model: {MODEL_NAME}")

    # CPU inference keeps GPU memory free for Qwen.
    model = SentenceTransformer(
        MODEL_NAME,
        device="cpu",
    )

    # Encode the full text of each policy.
    policy_ids = list(policies.keys())

    policy_texts = [
        (
            f"{policies[doc_id]['title']}. "
            f"{policies[doc_id]['content']}"
        )
        for doc_id in policy_ids
    ]

    policy_embeddings = model.encode(
        policy_texts,
        normalize_embeddings=True,
        convert_to_numpy=True,
    )

    # Encode all claims in one batch.
    claims = [
        case["claim"]
        for case in cases
    ]

    claim_embeddings = model.encode(
        claims,
        normalize_embeddings=True,
        convert_to_numpy=True,
    )

    results = []

    for index, case in enumerate(cases):
        cited_id = case["cited_document"]

        if cited_id not in policies:
            raise ValueError(
                f"Unknown cited policy: {cited_id}"
            )

        policy_index = policy_ids.index(cited_id)

        # Cosine similarity: vectors are normalized.
        similarity = float(
            np.dot(
                claim_embeddings[index],
                policy_embeddings[policy_index],
            )
        )

        rule_result = verify_grounding(
            claim=case["claim"],
            cited_document=cited_id,
        )

        # Similarity is evidence of relatedness only.
        # It must not override the rule-based verdict.
        result = {
            "test_id": case["test_id"],
            "attack_type": case["attack_type"],
            "claim": case["claim"],
            "cited_document": cited_id,
            "expected_result": case["expected_result"],
            "semantic_similarity": round(similarity, 4),
            "rule_based_status": rule_result["status"],
            "rule_based_reason": rule_result["reason"],
            "semantic_verdict": "not_determined",
            "explanation": (
                "Semantic similarity measures relatedness, "
                "not factual support or entailment."
            ),
        }

        results.append(result)

        print(f"\n{case['test_id']}")
        print(f"Attack type: {case['attack_type']}")
        print(f"Expected: {case['expected_result']}")
        print(f"Similarity: {similarity:.4f}")
        print(f"Rule status: {rule_result['status']}")

    supported = [
        item["semantic_similarity"]
        for item in results
        if item["expected_result"] == "supported"
    ]

    unsupported = [
        item["semantic_similarity"]
        for item in results
        if item["expected_result"] == "unsupported"
    ]

    summary = {
        "total_cases": len(results),
        "supported_cases": len(supported),
        "unsupported_cases": len(unsupported),
        "average_similarity_supported": (
            round(float(np.mean(supported)), 4)
            if supported else None
        ),
        "average_similarity_unsupported": (
            round(float(np.mean(unsupported)), 4)
            if unsupported else None
        ),
    }

    report = {
        "experiment": "24_semantic_grounding",
        "model": MODEL_NAME,
        "method": (
            "Normalized sentence embeddings and "
            "cosine similarity against cited policies"
        ),
        "limitations": (
            "Similarity cannot establish entailment, "
            "detect all contradictions, or prove truth."
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

    print("\n=== Experiment 24 Summary ===")

    for name, value in summary.items():
        print(f"{name}: {value}")

    print(f"Report saved: {OUTPUT_FILE}")
    print("\nExperiment 24 completed!")


if __name__ == "__main__":
    main()
