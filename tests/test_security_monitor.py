
from datetime import datetime, timedelta, timezone

from backend.security_monitor import analyze_security_events


NOW = datetime(
    2026, 10, 27, 12, 0, tzinfo=timezone.utc
)


def make_event(
    request_id,
    decision="supported_by_checks",
    minutes_ago=1,
    document="POL-005",
):
    return {
        "timestamp": (
            NOW - timedelta(minutes=minutes_ago)
        ).isoformat(),
        "event_type": "ai.security.evaluation",
        "request_id": request_id,
        "decision": decision,
        "cited_document": document,
    }


def test_empty_events():
    result = analyze_security_events(
        [],
        reference_time=NOW,
    )

    assert result["alert_count"] == 0


def test_failure_threshold():
    events = [
        make_event(
            f"error-{i}",
            decision="evaluation_error",
        )
        for i in range(3)
    ]

    result = analyze_security_events(
        events,
        reference_time=NOW,
    )

    assert result["alert_count"] == 1
    assert result["alerts"][0]["rule_id"] == "AI-MON-001"


def test_below_threshold():
    events = [
        make_event(
            f"error-{i}",
            decision="evaluation_error",
        )
        for i in range(2)
    ]

    result = analyze_security_events(
        events,
        reference_time=NOW,
    )

    assert result["alert_count"] == 0


def test_review_volume():
    events = [
        make_event(
            f"review-{i}",
            decision="review_required",
        )
        for i in range(4)
    ]

    result = analyze_security_events(
        events,
        reference_time=NOW,
    )

    assert any(
        alert["rule_id"] == "AI-MON-002"
        for alert in result["alerts"]
    )


def test_unrecognized_documents():
    events = [
        make_event(
            f"unknown-{i}",
            decision="review_required",
            document="UNRECOGNIZED",
        )
        for i in range(2)
    ]

    result = analyze_security_events(
        events,
        reference_time=NOW,
    )

    rule_ids = {
        alert["rule_id"]
        for alert in result["alerts"]
    }

    assert "AI-MON-003" in rule_ids


def test_old_events_excluded():
    events = [
        make_event(
            f"old-{i}",
            decision="evaluation_error",
            minutes_ago=10,
        )
        for i in range(3)
    ]

    result = analyze_security_events(
        events,
        reference_time=NOW,
    )

    assert result["alert_count"] == 0
    assert result["events_in_window"] == 0


def test_duplicate_request_ids():
    events = [
        make_event(
            "same-request",
            decision="evaluation_error",
        )
        for _ in range(5)
    ]

    result = analyze_security_events(
        events,
        reference_time=NOW,
    )

    assert result["alert_count"] == 0


def test_window_boundary():
    events = [
        make_event(
            f"boundary-{i}",
            decision="evaluation_error",
            minutes_ago=5,
        )
        for i in range(3)
    ]

    result = analyze_security_events(
        events,
        window_minutes=5,
        reference_time=NOW,
    )

    assert result["alert_count"] == 1


def test_unrelated_event_ignored():
    events = [
        {
            **make_event(
                f"other-{i}",
                decision="evaluation_error",
            ),
            "event_type": "application.startup",
        }
        for i in range(3)
    ]

    result = analyze_security_events(
        events,
        reference_time=NOW,
    )

    assert result["alert_count"] == 0
