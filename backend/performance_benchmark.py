
"""
Experiment 63 — Deployment Performance Benchmark.

Benchmarks safe, read-only HTTP endpoints.
Does not invoke Qwen, modify incidents, or execute
response actions.

Run inside Docker:
    python -m backend.performance_benchmark

Writes results to /app/results/performance_63.json.
"""

import base64
import json
import os
import statistics
import time
import urllib.error
import urllib.request

from datetime import datetime, timezone
from pathlib import Path


BASE_URL = "http://127.0.0.1:8000"
RESULT_PATH = Path("/app/results/performance_63.json")

HEALTH_REQUESTS = 50
MONITOR_REQUESTS = 20
WARMUP_REQUESTS = 5
REQUEST_TIMEOUT = 15


def percentile(values, percentage):
    """Nearest-rank percentile for latency samples."""
    if not values:
        raise ValueError("No latency samples")

    ordered = sorted(values)
    rank = max(
        1,
        -(-len(ordered) * percentage // 100),
    )

    return ordered[rank - 1]


def make_auth_header():
    username = os.environ.get("DASHBOARD_USERNAME")
    password = os.environ.get("DASHBOARD_PASSWORD")

    if not username or not password:
        raise RuntimeError(
            "Dashboard authentication is not configured"
        )

    raw = f"{username}:{password}".encode("utf-8")

    return "Basic " + base64.b64encode(
        raw
    ).decode("ascii")


def perform_request(path, authorization=None):
    headers = {}

    if authorization:
        headers["Authorization"] = authorization

    request = urllib.request.Request(
        BASE_URL + path,
        headers=headers,
        method="GET",
    )

    start = time.perf_counter()

    try:
        with urllib.request.urlopen(
            request,
            timeout=REQUEST_TIMEOUT,
        ) as response:
            response.read()
            status = response.status

    except urllib.error.HTTPError as exc:
        exc.read()
        status = exc.code

    duration_ms = (
        time.perf_counter() - start
    ) * 1000

    return status, duration_ms


def benchmark_endpoint(
    name,
    path,
    sample_count,
    authorization=None,
):
    for _ in range(WARMUP_REQUESTS):
        status, _ = perform_request(
            path,
            authorization,
        )

        if status != 200:
            raise RuntimeError(
                f"{name} warmup failed with HTTP {status}"
            )

    latencies = []
    failures = 0

    started = time.perf_counter()

    for _ in range(sample_count):
        try:
            status, duration_ms = perform_request(
                path,
                authorization,
            )

            if status == 200:
                latencies.append(duration_ms)
            else:
                failures += 1

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ):
            failures += 1

    elapsed = time.perf_counter() - started

    results = {
        "endpoint": name,
        "request_count": sample_count,
        "successful_requests": len(latencies),
        "failed_requests": failures,
        "elapsed_seconds": round(elapsed, 4),
        "throughput_rps": round(
            sample_count / elapsed,
            2,
        ) if elapsed > 0 else 0,
    }

    if latencies:
        results["latency_ms"] = {
            "min": round(min(latencies), 3),
            "average": round(
                statistics.mean(latencies),
                3,
            ),
            "p50": round(
                percentile(latencies, 50),
                3,
            ),
            "p95": round(
                percentile(latencies, 95),
                3,
            ),
            "p99": round(
                percentile(latencies, 99),
                3,
            ),
            "max": round(max(latencies), 3),
        }
    else:
        results["latency_ms"] = None

    return results


def main():
    authorization = make_auth_header()

    # Verify both endpoints before benchmarking.
    for path, auth in [
        ("/health", None),
        ("/agent/monitor", authorization),
    ]:
        status, _ = perform_request(path, auth)

        if status != 200:
            raise RuntimeError(
                f"Preflight failed for {path}: HTTP {status}"
            )

    print("Experiment 63 — Deployment Benchmark")
    print("Mode: sequential HTTP requests")
    print("AI inference: excluded")
    print()

    results = [
        benchmark_endpoint(
            name="health",
            path="/health",
            sample_count=HEALTH_REQUESTS,
        ),
        benchmark_endpoint(
            name="authenticated_agent_monitor",
            path="/agent/monitor",
            sample_count=MONITOR_REQUESTS,
            authorization=authorization,
        ),
    ]

    report = {
        "experiment": 63,
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "benchmark_mode": "sequential",
        "ai_inference_included": False,
        "results": results,
    }

    for result in results:
        print(result["endpoint"])
        print(
            f"  Successful: "
            f"{result['successful_requests']}/"
            f"{result['request_count']}"
        )
        print(
            f"  Throughput: "
            f"{result['throughput_rps']} req/s"
        )

        latency = result["latency_ms"]

        if latency:
            print(
                f"  Average: {latency['average']} ms"
            )
            print(
                f"  P50: {latency['p50']} ms"
            )
            print(
                f"  P95: {latency['p95']} ms"
            )
            print(
                f"  P99: {latency['p99']} ms"
            )

        print()

    RESULT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    RESULT_PATH.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(f"Report saved: {RESULT_PATH}")

    if any(
        item["failed_requests"]
        for item in results
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
