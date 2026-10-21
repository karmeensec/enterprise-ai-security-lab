
import time
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

print("=== Experiment 05: Instruction-Tuned LLM ===")

model_name = "Qwen/Qwen3-0.6B"
device = "cuda" if torch.cuda.is_available() else "cpu"

print(f"Model: {model_name}")
print(f"Device: {device}")

# Load tokenizer and pretrained model
tokenizer = AutoTokenizer.from_pretrained(model_name)

model = AutoModelForCausalLM.from_pretrained(
    model_name,
    dtype=torch.float16 if device == "cuda" else torch.float32
).to(device)

model.eval()

# Establish instructions and the user question
messages = [
    {
        "role": "system",
        "content": (
            "You are an enterprise cybersecurity assistant. "
            "Give clear, concise, technically accurate answers."
        )
    },
    {
        "role": "user",
        "content": (
            "Explain what prompt injection is in "
            "two short sentences."
        )
    }
]

# Format conversation using Qwen's chat template
inputs = tokenizer.apply_chat_template(
    messages,
    tokenize=True,
    add_generation_prompt=True,
    enable_thinking=False,
    return_dict=True,
    return_tensors="pt"
).to(device)

print("\n=== User Question ===")
print(messages[1]["content"])

if device == "cuda":
    torch.cuda.reset_peak_memory_stats()
    torch.cuda.synchronize()

start = time.perf_counter()

# Run model inference
with torch.inference_mode():
    outputs = model.generate(
        **inputs,
        max_new_tokens=120,
        do_sample=True,
        temperature=0.7,
        top_p=0.8,
        top_k=20,
        pad_token_id=tokenizer.eos_token_id
    )

if device == "cuda":
    torch.cuda.synchronize()

elapsed = time.perf_counter() - start

# Decode only newly generated tokens
new_tokens = outputs[0][inputs["input_ids"].shape[-1]:]
response = tokenizer.decode(
    new_tokens,
    skip_special_tokens=True
).strip()

print("\n=== AI Response ===")
print(response)

print("\n=== Performance ===")
print(f"Generated tokens: {len(new_tokens)}")
print(f"Inference time: {elapsed:.2f} seconds")
print(f"Tokens per second: {len(new_tokens) / elapsed:.2f}")

if device == "cuda":
    peak_memory = torch.cuda.max_memory_allocated() / 1024**3
    print(f"Peak PyTorch GPU allocation: {peak_memory:.2f} GB")

print(f"Model device: {next(model.parameters()).device}")
print("\nExperiment 05 completed!")
