
import pytest

from backend.inference_benchmark import (
    summarize_runs,
    validate_device,
)


def sample_runs():
    return [
        {
            "generation_seconds": 2.0,
            "generated_tokens": 20,
            "tokens_per_second": 10.0,
        },
        {
            "generation_seconds": 4.0,
            "generated_tokens": 40,
            "tokens_per_second": 10.0,
        },
        {
            "generation_seconds": 6.0,
            "generated_tokens": 30,
            "tokens_per_second": 5.0,
        },
    ]


def test_summary_run_count():
    result = summarize_runs(sample_runs())

    assert result["runs"] == 3


def test_average_generation_time():
    result = summarize_runs(sample_runs())

    assert result["average_generation_seconds"] == 4.0


def test_median_generation_time():
    result = summarize_runs(sample_runs())

    assert result["median_generation_seconds"] == 4.0


def test_aggregate_token_speed():
    result = summarize_runs(sample_runs())

    assert result["aggregate_tokens_per_second"] == 7.5


def test_empty_runs_rejected():
    with pytest.raises(ValueError):
        summarize_runs([])


def test_device_validation():
    validate_device("cuda", "cuda")

    with pytest.raises(RuntimeError):
        validate_device("cpu", "cuda")
