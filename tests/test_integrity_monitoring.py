
from datetime import datetime, timedelta, timezone

from backend.security_monitor import (
    analyze_security_events,
)


NOW = datetime(
    2026, 11, 4, 18, 0, tzinfo=timezone.utc
)


def integrity_event(request_id, minutes_ago=0):
    return {
        "timestamp": (
            NOW - timedelta(minutes=minutes_ago)
        ).isoformat(),
        "event_type": "ai.security.document_integrity_failure",
        "request_id": request_id,
        "route": "/chat/rag",
        "stage": "retrieval",
        "decision": "blocked",
        "review_required": True,
    }


def evaluation_event(request_id, decision):
    return {
        "timestamp": NOW.isoformat(),
        "event_type": "ai.security.evaluation",
        "request_id": request_id,
        "decision": decision,
        "cited_document": "POL-005",
    }


def get_rule(result, rule_id):
    return next(
        (
            alert
            for alert in result["alerts"]
            if alert["rule_id"] == rule_id
        ),
        None,
    )


def analyze(events, window=5):
    return analyze_security_events(
        events,
        window_minutes=window,
        reference_time=NOW,
    )


def test_single_integrity_failure_triggers_high_alert():
    result = analyze([integrity_event("req-001")])

    alert = get_rule(result, "AI-MON-004")

    assert alert is not None
    assert alert["severity"] == "high"
    assert alert["event_count"] == 1
    assert get_rule(result, "AI-MON-005") is None


def test_three_distinct_failures_trigger_critical_alert():
    events = [
        integrity_event("req-001", 0),
        integrity_event("req-002", 1),
        integrity_event("req-003", 2),
    ]

    result = analyze(events)

    critical = get_rule(result, "AI-MON-005")

    assert critical is not None
    assert critical["severity"] == "critical"
    assert critical["event_count"] == 3

    assert get_rule(result, "AI-MON-004") is not None


def test_duplicate_request_ids_do_not_trigger_critical():
    events = [
        integrity_event("req-001"),
        integrity_event("req-001"),
        integrity_event("req-002"),
    ]

    result = analyze(events)

    assert get_rule(result, "AI-MON-005") is None

    high = get_rule(result, "AI-MON-004")
    assert high["event_count"] == 2


def test_integrity_event_does_not_trigger_old_rules():
    result = analyze([
        integrity_event("req-001"),
        integrity_event("req-002"),
        integrity_event("req-003"),
        integrity_event("req-004"),
    ])

    assert get_rule(result, "AI-MON-001") is None
    assert get_rule(result, "AI-MON-002") is None
    assert get_rule(result, "AI-MON-003") is None


def test_old_evaluation_rule_still_works():
    events = [
        evaluation_event("req-001", "evaluation_error"),
        evaluation_event("req-002", "evaluation_error"),
        evaluation_event("req-003", "evaluation_error"),
    ]

    result = analyze(events)

    assert get_rule(result, "AI-MON-001") is not None
    assert get_rule(result, "AI-MON-004") is None


def test_critical_rule_uses_five_minute_window():
    events = [
        integrity_event("req-001", 0),
        integrity_event("req-002", 1),
        integrity_event("req-003", 8),
    ]

    result = analyze(events, window=15)

    high = get_rule(result, "AI-MON-004")

    assert high is not None
    assert high["event_count"] == 3

    # One event is outside the critical rule's
    # fixed five-minute window.
    assert get_rule(result, "AI-MON-005") is None


def test_events_outside_monitoring_window_ignored():
    result = analyze([
        integrity_event("req-old", 10)
    ])

    assert result["alert_count"] == 0
    assert result["events_in_window"] == 0
