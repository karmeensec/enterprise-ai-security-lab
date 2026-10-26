
import time
from functools import lru_cache
from threading import Lock

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM


MODEL_NAME = "Qwen/Qwen3-0.6B"

MAX_INPUT_TOKENS = 1024
MAX_NEW_TOKENS = 220


class InputTooLongError(ValueError):
    pass


class LLMService:
    def __init__(self):
        self.device = (
            "cuda" if torch.cuda.is_available() else "cpu"
        )
        self.lock = Lock()

        print(f"Loading {MODEL_NAME} on {self.device}...")

        self.tokenizer = AutoTokenizer.from_pretrained(
            MODEL_NAME
        )

        self.model = AutoModelForCausalLM.from_pretrained(
            MODEL_NAME,
            dtype=(
                torch.float16
                if self.device == "cuda"
                else torch.float32
            ),
        ).to(self.device)

        self.model.eval()
        print("AI model ready!")

    def generate(self, message: str):
        # Only one request generates text at a time.
        with self.lock:
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity education "
                        "assistant. Respond accurately in "
                        "2 to 4 concise sentences. "
                        "Distinguish facts from uncertainty. "
                        "Do not invent information."
                    ),
                },
                {
                    "role": "user",
                    "content": message,
                },
            ]

            inputs = self.tokenizer.apply_chat_template(
                messages,
                tokenize=True,
                add_generation_prompt=True,
                enable_thinking=False,
                return_dict=True,
                return_tensors="pt",
            )

            input_tokens = inputs["input_ids"].shape[-1]

            if input_tokens > MAX_INPUT_TOKENS:
                raise InputTooLongError(
                    "Input exceeds the configured token limit"
                )

            inputs = inputs.to(self.device)

            if self.device == "cuda":
                torch.cuda.synchronize()

            start = time.perf_counter()

            with torch.inference_mode():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=MAX_NEW_TOKENS,
                    do_sample=True,
                    temperature=0.7,
                    top_p=0.8,
                    top_k=20,
                    pad_token_id=self.tokenizer.eos_token_id,
                )

            if self.device == "cuda":
                torch.cuda.synchronize()

            elapsed = time.perf_counter() - start

            new_tokens = outputs[0][input_tokens:]
            generated_count = len(new_tokens)

            response = self.tokenizer.decode(
                new_tokens,
                skip_special_tokens=True,
            ).strip()

            # Approximate completion detection:
            # If generation used the entire allowance
            # without ending with an EOS token, it may
            # have stopped due to the length limit.
            final_token = (
                new_tokens[-1].item()
                if generated_count > 0 else None
            )

            eos_ids = self.model.generation_config.eos_token_id

            if eos_ids is None:
                eos_ids = self.tokenizer.eos_token_id

            if isinstance(eos_ids, int):
                eos_ids = [eos_ids]
            elif eos_ids is None:
                eos_ids = []

            ended_normally = final_token in eos_ids

            truncated = (
                generated_count >= MAX_NEW_TOKENS
                and not ended_normally
            )

            return {
                "response": response,
                "model": MODEL_NAME,
                "status": (
                    "incomplete" if truncated else "success"
                ),
                "generation_time_seconds": round(
                    elapsed, 3
                ),
                "input_tokens": input_tokens,
                "generated_tokens": generated_count,
                "truncated": truncated,
            }


@lru_cache(maxsize=1)
def get_llm_service():
    return LLMService()
