
import json
import re
import time
from pathlib import Path

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL_NAME = "Qwen/Qwen3-0.6B"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# Resolve the project root independent of terminal location
ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"
RESULTS_DIR.mkdir(exist_ok=True)

print("=== Experiment 07: AI Accuracy Evaluation ===")
print(f"Model: {MODEL_NAME}")
print(f"Device: {DEVICE}")

# Small, manually curated introductory dataset
TEST_CASES = [
    {
        "id": "CYB-001",
        "question": "What does SSO stand for?",
        "required": ["single sign-on"],
        "forbidden": ["saml stands for single sign-on"]
    },
    {
        "id": "CYB-002",
        "question": "What does SAML stand for?",
        "required": ["security assertion markup language"],
        "forbidden": []
    },
    {
        "id": "CYB-003",
        "question": "What does MFA stand for?",
        "required": ["multi-factor authentication"],
        "forbidden": []
    },
    {
        "id": "CYB-004",
        "question": "What is a firewall?",
        "required": ["traffic"],
        "forbidden": []
    },
    {
        "id": "CYB-005",
        "question": "What is prompt injection?",
        "required": ["instruction"],
        "forbidden": []
    }
]

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    dtype=torch.float16 if DEVICE == "cuda" else torch.float32
).to(DEVICE)

model.eval()


def normalize(text):
    # Case-insensitive and punctuation-tolerant comparisons
    text = text.lower().replace("-", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def evaluate_answer(answer, test_case):
    normalized = normalize(answer)

    missing = [
        phrase for phrase in test_case["required"]
        if normalize(phrase) not in normalized
    ]

    violations = [
        phrase for phrase in test_case["forbidden"]
        if normalize(phrase) in normalized
    ]

    return {
        "passed": not missing and not violations,
        "missing_required": missing,
        "forbidden_matches": violations
    }


results = []

for test in TEST_CASES:
    messages = [
        {
            "role": "system",
            "content": (
                "You are a cybersecurity education assistant. "
                "Give a technically accurate answer in one "
                "or two short sentences."
            )
        },
        {"role": "user", "content": test["question"]}
    ]

    inputs = tokenizer.apply_chat_template(
        messages,
        tokenize=True,
        add_generation_prompt=True,
        enable_thinking=False,
        return_dict=True,
        return_tensors="pt"
    ).to(DEVICE)

    start = time.perf_counter()

    # Fixed seed for reproducible sampling
    torch.manual_seed(42)

    with torch.inference_mode():
        output = model.generate(
            **inputs,
            max_new_tokens=160,
            do_sample=True,
            temperature=0.7,
            top_p=0.8,
            top_k=20,
            pad_token_id=tokenizer.eos_token_id
        )

    if DEVICE == "cuda":
        torch.cuda.synchronize()

    elapsed = time.perf_counter() - start

    generated_ids = output[0][inputs["input_ids"].shape[-1]:]
    answer = tokenizer.decode(
        generated_ids, skip_special_tokens=True
    ).strip()

    evaluation = evaluate_answer(answer, test)

    record = {
        "id": test["id"],
        "question": test["question"],
        "answer": answer,
        "seconds": round(elapsed, 3),
        **evaluation
    }

    results.append(record)

    status = "PASS" if evaluation["passed"] else "FAIL"

    print(f"\n[{test['id']}] {status}")
    print(f"Question: {test['question']}")
    print(f"Answer: {answer}")
    print(f"Time: {elapsed:.2f}s")


passed = sum(item["passed"] for item in results)
total = len(results)
score = passed / total * 100

report = {
    "experiment": "07_ai_accuracy_evaluation",
    "model": MODEL_NAME,
    "device": DEVICE,
    "scoring_method": "keyword heuristic, not factual accuracy",
    "passed": passed,
    "total": total,
    "pass_rate_percent": round(score, 2),
    "results": results
}

output_path = RESULTS_DIR / "07_accuracy_baseline.json"

with open(output_path, "w", encoding="utf-8") as file:
    json.dump(report, file, indent=2, ensure_ascii=False)

print("\n=== Evaluation Summary ===")
print(f"Keyword checks passed: {passed}/{total}")
print(f"Heuristic pass rate: {score:.1f}%")
print(f"Report saved: {output_path}")
print("\nExperiment 07 completed!")
