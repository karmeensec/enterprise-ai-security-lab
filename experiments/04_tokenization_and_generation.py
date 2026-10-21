
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

print("=== Experiment 04: Tokenization and Generation ===")

model_name = "distilbert/distilgpt2"
device = "cuda" if torch.cuda.is_available() else "cpu"

print(f"Device: {device}")
print(f"Model: {model_name}")

# Load our previously downloaded model
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name).to(device)
model.eval()

# Part 1: Explore tokenization
prompt = "Artificial intelligence is transforming cybersecurity."

tokens = tokenizer.encode(prompt)
token_strings = tokenizer.convert_ids_to_tokens(tokens)

print("\n=== Tokenization ===")
print(f"Original text: {prompt}")
print(f"Token IDs: {tokens}")
print(f"Token strings: {token_strings}")
print(f"Number of tokens: {len(tokens)}")

# Part 2: Compare generation strategies
generation_prompt = "The future of artificial intelligence"

inputs = tokenizer(
    generation_prompt, return_tensors="pt"
).to(device)

settings = [
    {"name": "Greedy", "do_sample": False},
    {"name": "Low temperature", "do_sample": True,
     "temperature": 0.3, "top_k": 40},
    {"name": "High temperature", "do_sample": True,
     "temperature": 1.2, "top_k": 40},
]

print("\n=== Generation Comparison ===")

for config in settings:
    name = config["name"]
    parameters = {k: v for k, v in config.items() if k != "name"}

    # Fixed seed for reproducibility
    torch.manual_seed(42)

    with torch.no_grad():
        output = model.generate(
            **inputs,
            max_new_tokens=35,
            pad_token_id=tokenizer.eos_token_id,
            **parameters
        )

    text = tokenizer.decode(
        output[0], skip_special_tokens=True
    )

    print(f"\n--- {name} ---")
    print(repr(text))

print("\nExperiment 04 completed!")
