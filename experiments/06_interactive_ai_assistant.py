
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL_NAME = "Qwen/Qwen3-0.6B"
MAX_HISTORY_MESSAGES = 6

device = "cuda" if torch.cuda.is_available() else "cpu"

print("=== Experiment 06: Interactive AI Assistant ===")
print(f"Loading {MODEL_NAME} on {device}...")

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    dtype=torch.float16 if device == "cuda" else torch.float32
).to(device)

model.eval()

system_message = {
    "role": "system",
    "content": (
        "You are an educational cybersecurity assistant. "
        "Answer in 2 to 4 concise sentences unless more detail "
        "is requested. Use technically accurate terminology. "
        "Distinguish related concepts such as SSO, SAML, and OAuth. "
        "If you are uncertain, say so rather than guessing."
    )
}

history = []

print("\nAI assistant ready!")
print("Type /exit to quit or /clear to reset the conversation.")

while True:
    try:
        user_input = input("\nYou: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nSession ended.")
        break

    if user_input.lower() == "/exit":
        print("Goodbye!")
        break

    if user_input.lower() == "/clear":
        history.clear()
        print("Conversation cleared.")
        continue

    if not user_input:
        continue

    messages = [
        system_message,
        *history[-MAX_HISTORY_MESSAGES:],
        {"role": "user", "content": user_input}
    ]

    inputs = tokenizer.apply_chat_template(
        messages,
        tokenize=True,
        add_generation_prompt=True,
        enable_thinking=False,
        return_dict=True,
        return_tensors="pt"
    ).to(device)

    with torch.inference_mode():
        output = model.generate(
            **inputs,
            max_new_tokens=300,
            do_sample=True,
            temperature=0.7,
            top_p=0.8,
            top_k=20,
            pad_token_id=tokenizer.eos_token_id
        )

    generated_ids = output[0][inputs["input_ids"].shape[-1]:]

    if len(generated_ids) >= 300:
        print("[Warning: Response may have reached the token limit]")

    response = tokenizer.decode(
        generated_ids,
        skip_special_tokens=True
    ).strip()

    print(f"\nAI: {response}")

    history.extend([
        {"role": "user", "content": user_input},
        {"role": "assistant", "content": response}
    ])
