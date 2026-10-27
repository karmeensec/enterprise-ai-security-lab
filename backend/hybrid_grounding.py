
from functools import lru_cache

import numpy as np
from sentence_transformers import CrossEncoder

from backend.grounding_validator import (
    load_policies,
    verify_grounding,
)


MODEL_NAME = "cross-encoder/nli-deberta-v3-small"

LABELS = [
    "contradiction",
    "entailment",
    "neutral",
]

# Experimental thresholds, not calibrated safety guarantees.
SUPPORT_THRESHOLD = 0.80
CONTRADICTION_THRESHOLD = 0.80


@lru_cache(maxsize=1)
def get_nli_model():
    print(f"Loading NLI model: {MODEL_NAME}")

    return CrossEncoder(
        MODEL_NAME,
        device="cpu",
        max_length=512,
    )


def get_nli_prediction(
    premise: str,
    hypothesis: str,
) -> dict:

    model = get_nli_model()

    logits = model.predict(
        [(premise, hypothesis)],
        batch_size=1,
        apply_softmax=False,
        convert_to_numpy=True,
        show_progress_bar=False,
    )

    scores = np.asarray(
        logits[0],
        dtype=np.float64,
    )

    shifted = scores - scores.max()
    probabilities = np.exp(shifted)
    probabilities /= probabilities.sum()

    index = int(np.argmax(probabilities))

    return {
        "label": LABELS[index],
        "confidence": round(
            float(probabilities[index]), 4
        ),
        "probabilities": {
            label: round(float(probabilities[i]), 4)
            for i, label in enumerate(LABELS)
        },
    }


def verify_hybrid_grounding(
    claim: str,
    cited_document: str,
) -> dict:

    cited_document = cited_document.upper().strip()

    policies = load_policies()

    if cited_document not in policies:
        return {
            "status": "unknown_source",
            "cited_document": cited_document,
            "rule_status": "unknown_source",
            "nli": None,
            "reason": "Cited policy does not exist.",
        }

    policy = policies[cited_document]

    premise = (
        f"{policy['title']}. "
        f"{policy['content']}"
    )

    rule_result = verify_grounding(
        claim=claim,
        cited_document=cited_document,
    )

    nli_result = get_nli_prediction(
        premise=premise,
        hypothesis=claim,
    )

    rule_status = rule_result["status"]
    nli_label = nli_result["label"]

    entailment_probability = (
        nli_result["probabilities"]["entailment"]
    )

    contradiction_probability = (
        nli_result["probabilities"]["contradiction"]
    )

    # Both independent checks must support approval.
    if (
        rule_status == "supported"
        and nli_label == "entailment"
        and entailment_probability >= SUPPORT_THRESHOLD
    ):
        status = "supported"
        reason = (
            "Rule-based and NLI checks agree on support."
        )

    # Both checks agree that evidence contradicts claim.
    elif (
        rule_status == "unsupported"
        and nli_label == "contradiction"
        and contradiction_probability >= CONTRADICTION_THRESHOLD
    ):
        status = "unsupported"
        reason = (
            "Rule-based and NLI checks agree on contradiction."
        )

    else:
        status = "needs_review"
        reason = (
            "Evidence is insufficient, confidence is below "
            "threshold, or the two validators disagree."
        )

    return {
        "status": status,
        "cited_document": cited_document,
        "rule_status": rule_status,
        "rule_reason": rule_result["reason"],
        "nli": nli_result,
        "reason": reason,
        "support_threshold": SUPPORT_THRESHOLD,
        "contradiction_threshold": CONTRADICTION_THRESHOLD,
    }
