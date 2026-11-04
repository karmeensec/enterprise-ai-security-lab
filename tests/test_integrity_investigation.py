
import pytest

from backend.investigation_service import (
    investigate_alert,
)


def make_integrity_event(request_id):
    return {
        "timestamp": "2026-11-04T18:00:00+00:00",
        "event_type": (
            "ai.security.document_integrity_failure"
        ),
        "request_id": request_id,
        "route": "/chat/rag",
        "stage": "retrieval",
        "decision": "blocked",
        "review_required": True,
    }


def make_alert(request_ids, rule_id="AI-MON-005"):
    return {
        "rule_id": rule_id,
        "rule_name": (
            "Repeated knowledge-base integrity failures"
        ),
        "severity": "critical",
        "request_ids": request_ids,
    }


def test_integrity_alert_evidence_found():
    events = [
        make_integrity_event("req-001"),
        make_integrity_event("req-002"),
        make_integrity_event("req-003"),
    ]

    result = investigate_alert(
        make_alert([
            "req-001",
            "req-002",
            "req-003",
        ]),
        events,
    )

    assert result["evidence_expected"] == 3
    assert result["evidence_found"] == 3
    assert result["evidence_missing"] == 0
    assert result["severity"] == "critical"


def test_integrity_evidence_contains_safe_metadata():
    result = investigate_alert(
        make_alert(["req-001"]),
        [make_integrity_event("req-001")],
    )

    evidence = result["events"][0]

    assert evidence["route"] == "/chat/rag"
    assert evidence["stage"] == "retrieval"
    assert evidence["decision"] == "blocked"

    assert "content" not in evidence
    assert "file_path" not in evidence
    assert "sha256" not in evidence
    assert "prompt" not in evidence


def test_missing_evidence_is_reported():
    result = investigate_alert(
        make_alert(["req-001", "req-999"]),
        [make_integrity_event("req-001")],
    )

    assert result["evidence_found"] == 1
    assert result["evidence_missing"] == 1
    assert result["missing_request_ids"] == [
        "req-999"
    ]


def test_duplicate_request_ids_not_double_counted():
    result = investigate_alert(
        make_alert(["req-001", "req-001"]),
        [make_integrity_event("req-001")],
    )

    assert result["evidence_expected"] == 1
    assert result["evidence_found"] == 1


def test_integrity_rule_ignores_evaluation_events():
    evaluation_event = {
        "timestamp": "2026-11-04T18:00:00+00:00",
        "event_type": "ai.security.evaluation",
        "request_id": "req-001",
        "decision": "evaluation_error",
        "cited_document": "POL-005",
    }

    result = investigate_alert(
        make_alert(["req-001"]),
        [evaluation_event],
    )

    assert result["evidence_found"] == 0
    assert result["evidence_missing"] == 1


def test_invalid_integrity_record_not_used():
    event = make_integrity_event("req-001")
    event["decision"] = "success"

    result = investigate_alert(
        make_alert(["req-001"]),
        [event],
    )

    assert result["evidence_found"] == 0


def test_too_many_evidence_ids_rejected():
    alert = make_alert(
        [f"req-{index}" for index in range(101)]
    )

    with pytest.raises(
        ValueError,
        match="Too many evidence",
    ):
        investigate_alert(alert, [])


def test_existing_evaluation_alert_still_supported():
    alert = {
        "rule_id": "AI-MON-001",
        "rule_name": "Repeated AI evaluation failures",
        "severity": "high",
        "request_ids": ["req-001"],
    }

    event = {
        "timestamp": "2026-11-04T18:00:00+00:00",
        "event_type": "ai.security.evaluation",
        "request_id": "req-001",
        "cited_document": "POL-002",
        "decision": "evaluation_error",
        "review_required": True,
        "duration_ms": 12.4,
    }

    result = investigate_alert(alert, [event])

    assert result["evidence_found"] == 1
    assert result["events"][0][
        "cited_document"
    ] == "POL-002"
