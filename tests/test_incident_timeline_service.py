
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

import backend.incident_timeline_service as service


CASE_ID = str(uuid4())
PLAN_ID = str(uuid4())
NOW = datetime.now(timezone.utc)


def timestamp(minutes=0):
    return (
        NOW + timedelta(minutes=minutes)
    ).isoformat()


@pytest.fixture
def sample_sources(monkeypatch):
    cases = [
        {
            "case_id": CASE_ID,
            "rule_id": "AI-MON-004",
            "request_ids": ["req-001"],
            "revision": 1,
            "status": "open",
            "disposition": "pending",
            "updated_at": timestamp(1),
        }
    ]

    responses = {
        "case_id": CASE_ID,
        "events": [
            {
                "timestamp": timestamp(2),
                "case_id": CASE_ID,
                "plan_id": PLAN_ID,
                "event_type": "plan_created",
                "action": "review_audit_logs",
                "status": "proposed",
                "execution_mode": "simulation_only",
            }
        ],
    }

    audits = {
        "events": [
            {
                "timestamp": timestamp(),
                "event_type": (
                    "ai.security.document_integrity_failure"
                ),
                "request_id": "req-001",
                "route": "/chat/rag",
                "stage": "retrieval",
                "decision": "blocked",
                "review_required": True,
            }
        ],
        "invalid_lines": 0,
    }

    monkeypatch.setattr(
        service,
        "load_case_history",
        lambda case_id: cases if case_id == CASE_ID else [],
    )

    monkeypatch.setattr(
        service,
        "load_response_timeline",
        lambda case_id: responses,
    )

    monkeypatch.setattr(
        service,
        "load_audit_events",
        lambda: audits,
    )

    return cases, responses, audits


def test_timeline_integrates_all_sources(sample_sources):
    result = service.load_incident_timeline(CASE_ID)

    assert result["event_count"] == 3
    assert result["investigation_event_count"] == 1
    assert result["security_event_count"] == 1
    assert result["response_event_count"] == 1
    assert result["source"] == "trusted_local_storage"
    assert result["read_only"] is True


def test_unknown_case_rejected(sample_sources):
    with pytest.raises(
        ValueError,
        match="not found",
    ):
        service.load_incident_timeline(str(uuid4()))


def test_invalid_case_id_rejected():
    with pytest.raises(
        ValueError,
        match="Invalid investigation case ID",
    ):
        service.load_incident_timeline("invalid")


def test_timeline_remains_simulation_only(sample_sources):
    result = service.load_incident_timeline(CASE_ID)

    assert result["simulation_only"] is True
    assert result["incident_confirmed"] is False

    assert all(
        event.get("execution_mode")
        in (None, "simulation_only")
        for event in result["events"]
    )
