
import pytest

from backend.investigation_service import (
    investigate_alert,
    MAX_EVIDENCE_REQUESTS,
)


def make_alert(request_ids=None):
    return {
        "rule_id": "AI-MON-001",
        "rule_name": "Repeated AI evaluation failures",
        "severity": "high",
        "request_ids": (
            ["req-001"] if request_ids is None else request_ids
        ),
    }


def make_event(
    request_id="req-001",
    decision="evaluation_error",
):
    return {
        "event_type": "ai.security.evaluation",
        "request_id": request_id,
        "timestamp": "2026-10-29T12:00:00+00:00",
        "cited_document": "POL-005",
        "decision": decision,
        "review_required": True,
        "duration_ms": 125.5,
    }


def test_single_evidence_match():
    result = investigate_alert(
        make_alert(),
        [make_event()],
    )

    assert result["evidence_found"] == 1
    assert result["evidence_missing"] == 0
    assert result["events"][0]["request_id"] == "req-001"


def test_multiple_evidence_matches():
    result = investigate_alert(
        make_alert(["req-001", "req-002"]),
        [
            make_event("req-001"),
            make_event("req-002"),
        ],
    )

    assert result["evidence_found"] == 2
    assert result["evidence_missing"] == 0


def test_missing_evidence():
    result = investigate_alert(
        make_alert(["req-001", "req-999"]),
        [make_event("req-001")],
    )

    assert result["evidence_found"] == 1
    assert result["evidence_missing"] == 1
    assert result["missing_request_ids"] == ["req-999"]


def test_duplicate_request_ids():
    result = investigate_alert(
        make_alert(["req-001", "req-001"]),
        [make_event()],
    )

    assert result["evidence_expected"] == 1
    assert result["evidence_found"] == 1


def test_unrelated_events_ignored():
    event = make_event()
    event["event_type"] = "application.startup"

    result = investigate_alert(
        make_alert(),
        [event],
    )

    assert result["evidence_found"] == 0
    assert result["evidence_missing"] == 1


def test_sensitive_content_excluded():
    event = make_event()
    event["claim"] = "PRIVATE_TEST_SECRET_123"
    event["prompt"] = "Confidential prompt"

    result = investigate_alert(
        make_alert(),
        [event],
    )

    evidence = result["events"][0]

    assert "claim" not in evidence
    assert "prompt" not in evidence
    assert "PRIVATE_TEST_SECRET_123" not in str(result)


def test_invalid_rule_id():
    with pytest.raises(ValueError):
        investigate_alert(
            {"rule_id": "", "request_ids": []},
            [],
        )


def test_invalid_request_ids_type():
    with pytest.raises(ValueError):
        investigate_alert(
            {"rule_id": "AI-MON-001", "request_ids": "req-001"},
            [],
        )


def test_too_many_request_ids():
    with pytest.raises(ValueError):
        investigate_alert(
            make_alert([
                f"req-{i}" for i in range(MAX_EVIDENCE_REQUESTS + 1)
            ]),
            [],
        )


def test_empty_request_id_rejected():
    with pytest.raises(ValueError):
        investigate_alert(
            make_alert([""]),
            [],
        )


def test_no_evidence():
    result = investigate_alert(
        make_alert([]),
        [],
    )

    assert result["evidence_expected"] == 0
    assert result["evidence_found"] == 0
    assert result["events"] == []


def test_evidence_order_matches_request_ids():
    result = investigate_alert(
        make_alert(["req-002", "req-001"]),
        [
            make_event("req-001"),
            make_event("req-002"),
        ],
    )

    assert [
        event["request_id"]
        for event in result["events"]
    ] == ["req-002", "req-001"]
