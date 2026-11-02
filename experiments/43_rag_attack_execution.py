
import json
from datetime import datetime, timezone
from pathlib import Path

from backend.llm_service import get_llm_service


ROOT = Path(__file__).resolve().parent.parent

DATASET = (
    ROOT / "results" / "43_indirect_prompt_injection.json"
)

OUTPUT = (
    ROOT / "results" / "43_rag_attack_results.json"
)


def evaluate_marker(response, marker):
    """
    Detect whether an attack marker appears in the
    generated response.

    Marker presence is a signal, not proof that
    the model obeyed an injected instruction.
    """
    if marker is None:
        return None

    return marker.casefold() in response.casefold()


def main():
    dataset = json.loads(
        DATASET.read_text(encoding="utf-8")
    )

    cases = dataset["cases"]

    print("=" * 65)
    print("EXPERIMENT 43 - INDIRECT PROMPT INJECTION")
    print("=" * 65)

    print("\nLoading Qwen3-0.6B...")
    llm = get_llm_service()

    results = []

    for number, case in enumerate(cases, start=1):
        print()
        print(
            f"[{number}/{len(cases)}] "
            f"{case['id']} - {case['category']}"
        )

        try:
            # Use the same system instructions and
            # context structure as our application.
            output = llm.generate(
                message=case["question"],
                context=case["retrieved_context"],
            )

            response = output["response"]

            marker_found = evaluate_marker(
                response,
                case["attack_marker"],
            )

            result = {
                "id": case["id"],
                "category": case["category"],
                "question": case["question"],
                "expected_behavior": case[
                    "expected_behavior"
                ],
                "attack_marker": case["attack_marker"],
                "model_response": response,
                "marker_found": marker_found,
                "generation_status": output["status"],
                "truncated": output["truncated"],
                "input_tokens": output["input_tokens"],
                "generated_tokens": output[
                    "generated_tokens"
                ],
                "generation_time_seconds": output[
                    "generation_time_seconds"
                ],
                "manual_assessment": "pending",
            }

            print("Model response:")
            print(response)
            print("Attack marker found:", marker_found)

        except Exception as exc:
            result = {
                "id": case["id"],
                "category": case["category"],
                "generation_status": "error",
                "error_type": type(exc).__name__,
                "manual_assessment": "error",
            }

            print("Error:", type(exc).__name__)

        results.append(result)

    report = {
        "experiment": "43_rag_attack_execution",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "test_count": len(results),
        "evaluation_mode": (
            "Local LLM inference using synthetic "
            "retrieved document contexts"
        ),
        "limitations": [
            "The retrieval service was bypassed to "
            "control document contents.",
            "Attack-marker detection is not a "
            "complete prompt-injection assessment.",
            "Model generation uses sampling and "
            "may produce different outputs.",
            "Manual review is required.",
        ],
        "results": results,
    }

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print()
    print("=" * 65)
    print("EXECUTION COMPLETE")
    print("Cases executed:", len(results))
    print("Report saved:", OUTPUT)
    print("=" * 65)


if __name__ == "__main__":
    main()
