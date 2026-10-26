
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"

INPUT_FILE = RESULTS_DIR / "07_accuracy_baseline.json"
OUTPUT_FILE = RESULTS_DIR / "08_improved_evaluation.json"

print("=== Experiment 08: Improved AI Evaluation ===")

# These are initial, manually curated checks.
# They do not replace expert factual review.
RULES = {
    "CYB-001": {
        "concepts": ["single sign on"],
        "known_errors": [],
    },
    "CYB-002": {
        "concepts": ["security assertion markup language"],
        "known_errors": [
            "secure single sign in",
            "secure single sign on",
        ],
    },
    "CYB-003": {
        "concepts": ["multi factor authentication"],
        "known_errors": [],
    },
    "CYB-004": {
        "concepts": ["traffic"],
        "known_errors": [],
    },
    "CYB-005": {
        "concepts": ["instruction"],
        "known_errors": [],
    },
}


def normalize(text):
    text = text.lower().replace("-", " ")
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def evaluate(record):
    rule = RULES.get(record["id"])

    if rule is None:
        return "REVIEW", "No evaluation rule exists"

    answer = normalize(record["answer"])

    errors = [
        phrase for phrase in rule["known_errors"]
        if normalize(phrase) in answer
    ]

    missing = [
        phrase for phrase in rule["concepts"]
        if normalize(phrase) not in answer
    ]

    if errors:
        return "FAIL", f"Known factual error: {errors}"

    if missing:
        return "REVIEW", (
            f"Missing expected concept: {missing}. "
            "Human review required."
        )

    return "PASS", "Automated checks satisfied; not expert-verified"


if not INPUT_FILE.exists():
    raise FileNotFoundError(
        f"Missing baseline report: {INPUT_FILE}"
    )

with INPUT_FILE.open("r", encoding="utf-8") as file:
    baseline = json.load(file)

evaluated = []

for record in baseline["results"]:
    status, explanation = evaluate(record)

    evaluated.append({
        "id": record["id"],
        "question": record["question"],
        "answer": record["answer"],
        "previous_keyword_pass": record["passed"],
        "new_status": status,
        "explanation": explanation,
    })

    print(f"\n[{record['id']}] {status}")
    print(f"Question: {record['question']}")
    print(f"Reason: {explanation}")

counts = Counter(item["new_status"] for item in evaluated)

report = {
    "experiment": "08_improved_ai_evaluation",
    "source": INPUT_FILE.name,
    "method": "Deterministic heuristic triage",
    "limitations": (
        "Automated PASS does not establish factual correctness. "
        "REVIEW requires human assessment."
    ),
    "summary": {
        "pass": counts["PASS"],
        "fail": counts["FAIL"],
        "review": counts["REVIEW"],
        "total": len(evaluated),
    },
    "results": evaluated,
}

with OUTPUT_FILE.open("w", encoding="utf-8") as file:
    json.dump(report, file, indent=2, ensure_ascii=False)

print("\n=== Evaluation Summary ===")
print(f"PASS: {counts['PASS']}")
print(f"FAIL: {counts['FAIL']}")
print(f"REVIEW: {counts['REVIEW']}")
print(f"TOTAL: {len(evaluated)}")
print(f"Report saved: {OUTPUT_FILE}")
print("\nExperiment 08 completed!")
