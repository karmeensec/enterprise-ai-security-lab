
import json
import uuid
from datetime import datetime, timezone

from backend.log_monitor_service import (
    load_audit_events,
)


def make_event(event_type):
    common = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "event_type": event_type,
        "request_id": str(uuid.uuid4()),
        "decision": "blocked",
    }

    if event_type == "ai.security.document_integrity_failure":
        common.update({
            "route": "/chat/rag",
            "stage": "retrieval",
            "review_required": True,
        })
    else:
        common.update({
            "cited_document": "POL-005",
        })

    return common


def test_load_integrity_failure(tmp_path):
    path = tmp_path / "audit.jsonl"

    event = make_event(
        "ai.security.document_integrity_failure"
    )

    path.write_text(
        json.dumps(event) + "\n",
        encoding="utf-8",
    )

    result = load_audit_events(path)

    assert result["valid_events"] == 1
    assert result["invalid_lines"] == 0
    assert result["events"][0] == event


def test_load_mixed_audit_events(tmp_path):
    path = tmp_path / "audit.jsonl"

    events = [
        make_event("ai.security.evaluation"),
        make_event(
            "ai.security.document_integrity_failure"
        ),
    ]

    path.write_text(
        "\n".join(json.dumps(e) for e in events) + "\n",
        encoding="utf-8",
    )

    result = load_audit_events(path)

    assert result["valid_events"] == 2
    assert result["invalid_lines"] == 0


def test_malformed_integrity_event_rejected(tmp_path):
    path = tmp_path / "audit.jsonl"

    event = make_event(
        "ai.security.document_integrity_failure"
    )

    event.pop("stage")

    path.write_text(
        json.dumps(event) + "\n",
        encoding="utf-8",
    )

    result = load_audit_events(path)

    assert result["valid_events"] == 0
    assert result["invalid_lines"] == 1


def test_integrity_event_requires_block_decision(tmp_path):
    path = tmp_path / "audit.jsonl"

    event = make_event(
        "ai.security.document_integrity_failure"
    )
    event["decision"] = "success"

    path.write_text(
        json.dumps(event) + "\n",
        encoding="utf-8",
    )

    result = load_audit_events(path)

    assert result["valid_events"] == 0
    assert result["invalid_lines"] == 1
