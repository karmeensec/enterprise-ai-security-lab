
import time
from functools import lru_cache
from threading import Lock

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM


MODEL_NAME = "Qwen/Qwen3-0.6B"


class LLMService:
    def __init__(self):
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.lock = Lock()

        print(f"Loading {MODEL_NAME} on {self.device}...")

        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

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
        # Serialize generation to limit concurrent GPU usage.
        with self.lock:
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are an enterprise cybersecurity "
                        "education assistant. Give clear, concise "
                        "answers. Do not invent facts. "
                        "Acknowledge uncertainty when appropriate."
                    ),
                },
                {"role": "user", "content": message},
            ]

            inputs = self.tokenizer.apply_chat_template(
                messages,
                tokenize=True,
                add_generation_prompt=True,
                enable_thinking=False,
                return_dict=True,
                return_tensors="pt",
            ).to(self.device)

            if self.device == "cuda":
                torch.cuda.synchronize()

            start = time.perf_counter()

            with torch.inference_mode():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=160,
                    do_sample=True,
                    temperature=0.7,
                    top_p=0.8,
                    top_k=20,
                    pad_token_id=self.tokenizer.eos_token_id,
                )

            if self.device == "cuda":
                torch.cuda.synchronize()

            elapsed = time.perf_counter() - start

            new_tokens = outputs[0][
                inputs["input_ids"].shape[-1]:
            ]

            response = self.tokenizer.decode(
                new_tokens,
                skip_special_tokens=True,
            ).strip()

            return {
                "response": response,
                "model": MODEL_NAME,
                "status": "success",
                "generation_time_seconds": round(elapsed, 3),
            }


@lru_cache(maxsize=1)
def get_llm_service():
    return LLMService()
