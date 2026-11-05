
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from backend.unified_case_timeline import (
    UnifiedTimelineError,
    build_unified_case_timeline,
)


CASE_ID = str(uuid4())
PLAN_ID = str(uuid4())

BASE_TIME = datetime(
    2026, 11, 5, 12, 0, tzinfo=timezone.utc
)


def at(minutes):
    return (
        BASE_TIME + timedelta(minutes=minutes)
    ).isoformat()


def case_revision(
    revision=1,
    status="open",
    minutes=1,
):
    return {
        "case_id": CASE_ID,
        "rule_id": "AI-MON-005",
        "request_ids": ["req-001", "req-002"],
        "revision": revision,
        "status": status,
        "disposition": "pending",
        "updated_at": at(minutes),
        "notes": "Private investigation notes",
        "analyst": "internal-analyst",
    }


def response_timeline():
    return {
        "case_id": CASE_ID,
        "events": [
            {
                "timestamp": at(3),
                "case_id": CASE_ID,
                "plan_id": PLAN_ID,
                "event_type": "plan_created",
                "action": "disable_account",
                "status": "pending_approval",
                "execution_mode": "simulation_only",
                "notes": "Private response notes",
            },
            {
                "timestamp": at(4),
                "case_id": CASE_ID,
                "plan_id": PLAN_ID,
                "event_type": "plan_reviewed",
                "action": "disable_account",
                "status": "approved_for_simulation",
                "execution_mode": "simulation_only",
            },
            {
                "timestamp": at(5),
                "case_id": CASE_ID,
                "plan_id": PLAN_ID,
                "event_type": "simulation_completed",
                "action": "disable_account",
                "status": "completed",
                "execution_mode": "simulation_only",
                "real_action_executed": False,
            },
        ],
    }


def audit_event(
    request_id="req-001",
    minutes=0,
):
    return {
        "timestamp": at(minutes),
        "event_type": (
            "ai.security.document_integrity_failure"
        ),
        "request_id": request_id,
        "route": "/chat/rag",
        "stage": "retrieval",
        "decision": "blocked",
        "review_required": True,
        "secret": "do-not-expose",
    }


def build(
    cases=None,
    responses=None,
    audits=None,
):
    return build_unified_case_timeline(
        case_history=(
            [case_revision()]
            if cases is None
            else cases
        ),
        response_timeline=(
            response_timeline()
            if responses is None
            else responses
        ),
        audit_events=(
            [audit_event()]
            if audits is None
            else audits
        ),
    )


def test_complete_unified_timeline():
    result = build()

    assert result["event_count"] == 5
    assert result["investigation_event_count"] == 1
    assert result["security_event_count"] == 1
    assert result["response_event_count"] == 3


def test_events_sorted_chronologically():
    result = build()

    timestamps = [
        item["timestamp"]
        for item in result["events"]
    ]

    assert timestamps == sorted(timestamps)


def test_unrelated_audit_events_are_excluded():
    result = build(
        audits=[
            audit_event("req-001"),
            audit_event("unrelated-request"),
        ]
    )

    assert result["security_event_count"] == 1


def test_duplicate_audit_events_not_counted_twice():
    event = audit_event()

    result = build(
        audits=[event, deepcopy(event)]
    )

    assert result["security_event_count"] == 1


def test_multiple_investigation_revisions():
    result = build(
        cases=[
            case_revision(),
            case_revision(
                revision=2,
                status="investigating",
                minutes=2,
            ),
        ]
    )

    assert result["investigation_event_count"] == 2


def test_sensitive_fields_not_exposed():
    result = build()

    for event in result["events"]:
        assert "secret" not in event
        assert "notes" not in event
        assert "analyst" not in event
        assert "target" not in event


def test_mismatched_response_case_rejected():
    response = response_timeline()
    response["case_id"] = str(uuid4())

    with pytest.raises(
        UnifiedTimelineError,
        match="another case",
    ):
        build(responses=response)


def test_invalid_revision_sequence_rejected():
    with pytest.raises(
        UnifiedTimelineError,
        match="revision sequence",
    ):
        build(
            cases=[
                case_revision(revision=1),
                case_revision(revision=3),
            ]
        )


def test_real_execution_claim_rejected():
    response = response_timeline()

    response["events"][-1][
        "real_action_executed"
    ] = True

    with pytest.raises(
        UnifiedTimelineError,
        match="Invalid simulation security state",
    ):
        build(responses=response)


def test_original_sources_remain_unchanged():
    cases = [case_revision()]
    responses = response_timeline()
    audits = [audit_event()]

    originals = deepcopy(
        (cases, responses, audits)
    )

    build(
        cases=cases,
        responses=responses,
        audits=audits,
    )

    assert (cases, responses, audits) == originals


def test_confirmed_incident_requires_disposition():
    case = case_revision()
    case["status"] = "resolved"
    case["disposition"] = "confirmed_incident"

    result = build(cases=[case])

    assert result["incident_confirmed"] is True


def test_detected_alert_is_not_confirmed_incident():
    result = build()

    assert result["incident_confirmed"] is False
