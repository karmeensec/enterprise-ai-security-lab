
"""
Experiment 64 — Qwen CPU vs GPU Inference Benchmark.

Reuses the existing LLMService and Qwen3-0.6B model.

Runs one warmup and three measured generations.
Model generation is limited to 96 tokens for benchmarking.

Examples:

Windows GPU:
    python -m backend.inference_benchmark \
        --expected-device cuda \
        --output results/64_gpu.json

Docker CPU:
    python -m backend.inference_benchmark \
        --expected-device cpu \
        --output /app/results/64_cpu.json

No security actions or agent tools are executed.
"""

import argparse
import json
import statistics
import time

from datetime import datetime, timezone
from pathlib import Path

import psutil
import torch

import backend.llm_service as llm_module


PROMPT = (
    "Explain why multi-factor authentication is "
    "important for enterprise cybersecurity. "
    "Include one practical example."
)

WARMUP_RUNS = 1
MEASURED_RUNS = 3
BENCHMARK_MAX_NEW_TOKENS = 96


def memory_mb() -> float:
    process = psutil.Process()
    return round(
        process.memory_info().rss / (1024 ** 2),
        2,
    )


def validate_device(
    actual: str,
    expected: str,
) -> None:
    if actual != expected:
        raise RuntimeError(
            f"Expected {expected}, but model uses {actual}"
        )


def summarize_runs(runs: list[dict]) -> dict:
    if not runs:
        raise ValueError("No benchmark runs")

    durations = [
        run["generation_seconds"]
        for run in runs
    ]

    tokens = [
        run["generated_tokens"]
        for run in runs
    ]

    rates = [
        run["tokens_per_second"]
        for run in runs
    ]

    total_seconds = sum(durations)
    total_tokens = sum(tokens)

    return {
        "runs": len(runs),
        "average_generation_seconds": round(
            statistics.mean(durations), 3
        ),
        "median_generation_seconds": round(
            statistics.median(durations), 3
        ),
        "minimum_generation_seconds": round(
            min(durations), 3
        ),
        "maximum_generation_seconds": round(
            max(durations), 3
        ),
        "average_generated_tokens": round(
            statistics.mean(tokens), 2
        ),
        "average_tokens_per_second": round(
            statistics.mean(rates), 2
        ),
        "aggregate_tokens_per_second": round(
            total_tokens / total_seconds, 2
        ) if total_seconds > 0 else 0,
    }


def run_benchmark(
    expected_device: str,
) -> dict:
    # This changes the limit only in this benchmark process.
    # It does not modify llm_service.py on disk.
    llm_module.MAX_NEW_TOKENS = (
        BENCHMARK_MAX_NEW_TOKENS
    )

    print("Experiment 64 — Qwen Inference Benchmark")
    print(f"Model: {llm_module.MODEL_NAME}")
    print(f"Expected device: {expected_device}")
    print()

    memory_before_load = memory_mb()

    load_start = time.perf_counter()
    service = llm_module.get_llm_service()
    load_seconds = (
        time.perf_counter() - load_start
    )

    validate_device(
        service.device,
        expected_device,
    )

    memory_after_load = memory_mb()

    print(f"Actual device: {service.device}")
    print(f"Model load time: {load_seconds:.2f} s")
    print()

    if service.device == "cuda":
        torch.cuda.synchronize()
        torch.cuda.reset_peak_memory_stats()

    print("Running warmup...")

    for _ in range(WARMUP_RUNS):
        service.generate(PROMPT)

    if service.device == "cuda":
        torch.cuda.synchronize()
        torch.cuda.reset_peak_memory_stats()

    runs = []

    for index in range(1, MEASURED_RUNS + 1):
        print(f"Measured run {index}/{MEASURED_RUNS}")

        wall_start = time.perf_counter()
        result = service.generate(PROMPT)

        wall_seconds = (
            time.perf_counter() - wall_start
        )

        generation_seconds = float(
            result["generation_time_seconds"]
        )

        generated_tokens = int(
            result["generated_tokens"]
        )

        rate = (
            generated_tokens / generation_seconds
            if generation_seconds > 0
            else 0.0
        )

        run = {
            "run": index,
            "status": result["status"],
            "input_tokens": int(
                result["input_tokens"]
            ),
            "generated_tokens": generated_tokens,
            "generation_seconds": generation_seconds,
            "wall_seconds": round(
                wall_seconds, 3
            ),
            "tokens_per_second": round(
                rate, 2
            ),
            "truncated": bool(
                result["truncated"]
            ),
        }

        runs.append(run)

        print(
            f"  {generated_tokens} tokens "
            f"in {generation_seconds:.3f} s "
            f"({rate:.2f} tokens/s)"
        )

    summary = summarize_runs(runs)

    memory_after_runs = memory_mb()

    peak_gpu_memory_mb = None

    if service.device == "cuda":
        torch.cuda.synchronize()

        peak_gpu_memory_mb = round(
            torch.cuda.max_memory_allocated()
            / (1024 ** 2),
            2,
        )

    report = {
        "experiment": 64,
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "model": llm_module.MODEL_NAME,
        "device": service.device,
        "torch_version": torch.__version__,
        "generation_limit": (
            BENCHMARK_MAX_NEW_TOKENS
        ),
        "sampling_mode": "production_settings",
        "warmup_runs": WARMUP_RUNS,
        "measured_runs": MEASURED_RUNS,
        "model_load_seconds": round(
            load_seconds, 3
        ),
        "process_memory_mb": {
            "before_model_load": memory_before_load,
            "after_model_load": memory_after_load,
            "after_benchmark": memory_after_runs,
        },
        "peak_cuda_allocated_mb": (
            peak_gpu_memory_mb
        ),
        "summary": summary,
        "runs": runs,
    }

    print()
    print("Benchmark summary")
    print(
        f"Average generation: "
        f"{summary['average_generation_seconds']} s"
    )
    print(
        f"Aggregate generation speed: "
        f"{summary['aggregate_tokens_per_second']} "
        "tokens/s"
    )
    print(
        f"Process RAM after benchmark: "
        f"{memory_after_runs} MB"
    )

    if peak_gpu_memory_mb is not None:
        print(
            f"Peak GPU allocated memory: "
            f"{peak_gpu_memory_mb} MB"
        )

    return report


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--expected-device",
        choices=("cuda", "cpu"),
        required=True,
    )

    parser.add_argument(
        "--output",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    report = run_benchmark(
        args.expected_device
    )

    args.output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    args.output.write_text(
        json.dumps(
            report,
            indent=2,
        ),
        encoding="utf-8",
    )

    print()
    print(f"Report saved: {args.output}")


if __name__ == "__main__":
    main()
