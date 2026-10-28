
import json
from datetime import datetime, timedelta, timezone

import pytest

import backend.log_monitor_service as monitor


def make_event(
    request_id,
    decision="supported_by_checks",
    timestamp=None,
):
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    return {
        "timestamp": timestamp.isoformat(),
        "event_type": "ai.security.evaluation",
        "request_id": request_id,
        "cited_document": "POL-005",
        "decision": decision,
        "review_required": decision != "supported_by_checks",
        "duration_ms": 100.0,
    }


def write_events(path, events):
    with path.open("w", encoding="utf-8") as file:
        for event in events:
            file.write(json.dumps(event) + "\n")


def test_missing_audit_file(tmp_path):
    result = monitor.load_audit_events(
        tmp_path / "missing.jsonl"
    )

    assert result["file_exists"] is False
    assert result["valid_events"] == 0
    assert result["invalid_lines"] == 0


def test_load_valid_events(tmp_path):
    path = tmp_path / "audit.jsonl"

    write_events(path, [
        make_event("request-1"),
        make_event("request-2"),
    ])

    result = monitor.load_audit_events(path)

    assert result["valid_events"] == 2
    assert result["invalid_lines"] == 0


def test_malformed_lines_are_counted(tmp_path):
    path = tmp_path / "audit.jsonl"

    with path.open("w", encoding="utf-8") as file:
        file.write("{invalid-json}\n")
        file.write(json.dumps(make_event("valid-1")) + "\n")

    result = monitor.load_audit_events(path)

    assert result["valid_events"] == 1
    assert result["invalid_lines"] == 1


def test_unrelated_events_are_ignored(tmp_path):
    path = tmp_path / "audit.jsonl"

    event = make_event("startup-1")
    event["event_type"] = "application.startup"

    write_events(path, [event])

    result = monitor.load_audit_events(path)

    assert result["valid_events"] == 0
    assert result["invalid_lines"] == 0


def test_old_events_do_not_trigger_alerts(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "audit.jsonl"
    old = datetime.now(timezone.utc) - timedelta(
        minutes=15
    )

    write_events(path, [
        make_event(
            f"old-error-{i}",
            "evaluation_error",
            old,
        )
        for i in range(3)
    ])

    monkeypatch.setattr(monitor, "AUDIT_FILE", path)

    result = monitor.run_live_monitor()

    assert result["valid_events_loaded"] == 3
    assert result["monitoring"]["alert_count"] == 0


def test_recent_errors_trigger_alert(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "audit.jsonl"
    recent = datetime.now(timezone.utc) - timedelta(
        seconds=30
    )

    write_events(path, [
        make_event(
            f"recent-error-{i}",
            "evaluation_error",
            recent,
        )
        for i in range(3)
    ])

    monkeypatch.setattr(monitor, "AUDIT_FILE", path)

    result = monitor.run_live_monitor()

    assert result["monitoring"]["alert_count"] == 1

    alert = result["monitoring"]["alerts"][0]

    assert alert["rule_id"] == "AI-MON-001"
    assert alert["severity"] == "high"
    assert alert["event_count"] == 3


def test_missing_timezone_rejected(tmp_path):
    path = tmp_path / "audit.jsonl"

    event = make_event("bad-time")
    event["timestamp"] = "2026-10-27T12:00:00"

    write_events(path, [event])

    result = monitor.load_audit_events(path)

    assert result["valid_events"] == 0
    assert result["invalid_lines"] == 1


def test_file_size_limit(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    path.write_text("1234567890", encoding="utf-8")

    monkeypatch.setattr(
        monitor,
        "MAX_AUDIT_FILE_BYTES",
        5,
    )

    with pytest.raises(ValueError):
        monitor.load_audit_events(path)
