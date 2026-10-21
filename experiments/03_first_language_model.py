
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

print("=== Experiment 03: First Language Model ===")

model_name = "distilbert/distilgpt2"
device = "cuda" if torch.cuda.is_available() else "cpu"

print(f"Device: {device}")
print(f"Model: {model_name}")

# Load the tokenizer
tokenizer = AutoTokenizer.from_pretrained(model_name)

# Load the pretrained language model
model = AutoModelForCausalLM.from_pretrained(model_name)
model = model.to(device)
model.eval()

# Our first text-generation prompt
prompt = "Artificial intelligence is transforming"

# Convert text into numerical tokens
inputs = tokenizer(prompt, return_tensors="pt").to(device)

print(f"\nInput: {prompt}")
print(f"Input tokens: {inputs['input_ids'].shape[1]}")

# Generate text without training the model
with torch.no_grad():
    output = model.generate(
        **inputs,
        max_new_tokens=40,
        do_sample=False,
        pad_token_id=tokenizer.eos_token_id
    )

# Convert generated tokens back into text
generated_text = tokenizer.decode(
    output[0], skip_special_tokens=True
)

print("\n=== Generated Text ===")
print(generated_text)

print("\n=== Model Information ===")
print(f"Model device: {next(model.parameters()).device}")
print(f"Parameters: {sum(p.numel() for p in model.parameters()):,}")

print("\nExperiment completed!")
