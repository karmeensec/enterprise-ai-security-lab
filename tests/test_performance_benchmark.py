
import pytest

import backend.performance_benchmark as benchmark


def test_percentile_median():
    assert benchmark.percentile(
        [1, 2, 3, 4, 5],
        50,
    ) == 3


def test_percentile_95():
    assert benchmark.percentile(
        list(range(1, 101)),
        95,
    ) == 95


def test_percentile_99():
    assert benchmark.percentile(
        list(range(1, 101)),
        99,
    ) == 99


def test_percentile_empty_samples():
    with pytest.raises(ValueError):
        benchmark.percentile([], 95)


def test_authentication_missing_fails_closed(
    monkeypatch,
):
    monkeypatch.delenv(
        "DASHBOARD_USERNAME",
        raising=False,
    )
    monkeypatch.delenv(
        "DASHBOARD_PASSWORD",
        raising=False,
    )

    with pytest.raises(RuntimeError):
        benchmark.make_auth_header()


def test_authentication_header_uses_basic(
    monkeypatch,
):
    monkeypatch.setenv(
        "DASHBOARD_USERNAME",
        "test-user",
    )
    monkeypatch.setenv(
        "DASHBOARD_PASSWORD",
        "test-password",
    )

    header = benchmark.make_auth_header()

    assert header.startswith("Basic ")
    assert "test-password" not in header


def test_benchmark_statistics(monkeypatch):
    durations = iter([2.0, 4.0, 6.0, 8.0])

    def fake_request(path, authorization=None):
        if next_call[0] < benchmark.WARMUP_REQUESTS:
            next_call[0] += 1
            return 200, 1.0

        return 200, next(durations)

    next_call = [0]

    monkeypatch.setattr(
        benchmark,
        "perform_request",
        fake_request,
    )

    result = benchmark.benchmark_endpoint(
        "test",
        "/health",
        sample_count=4,
    )

    assert result["successful_requests"] == 4
    assert result["failed_requests"] == 0
    assert result["latency_ms"]["average"] == 5.0
    assert result["latency_ms"]["p50"] == 4.0
    assert result["latency_ms"]["p95"] == 8.0


def test_non_200_response_counted_as_failure(
    monkeypatch,
):
    calls = [0]

    def fake_request(path, authorization=None):
        calls[0] += 1

        if calls[0] <= benchmark.WARMUP_REQUESTS:
            return 200, 1.0

        return 503, 2.0

    monkeypatch.setattr(
        benchmark,
        "perform_request",
        fake_request,
    )

    result = benchmark.benchmark_endpoint(
        "test",
        "/health",
        sample_count=3,
    )

    assert result["successful_requests"] == 0
    assert result["failed_requests"] == 3
    assert result["latency_ms"] is None
