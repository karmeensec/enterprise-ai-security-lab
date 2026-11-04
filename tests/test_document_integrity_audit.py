
import json
import uuid

import pytest

import backend.audit_logger as audit_module


@pytest.fixture
def temporary_audit_file(tmp_path, monkeypatch):
    audit_file = tmp_path / "security_audit.jsonl"

    monkeypatch.setattr(
        audit_module,
        "AUDIT_DIRECTORY",
        tmp_path,
    )

    monkeypatch.setattr(
        audit_module,
        "AUDIT_FILE",
        audit_file,
    )

    return audit_file


def test_integrity_failure_event_recorded(
    temporary_audit_file,
):
    request_id = str(uuid.uuid4())

    event = (
        audit_module.record_document_integrity_failure(
            request_id=request_id,
            route="/chat/rag",
        )
    )

    assert event["event_type"] == (
        "ai.security.document_integrity_failure"
    )

    assert event["decision"] == "blocked"
    assert event["review_required"] is True
    assert event["request_id"] == request_id

    saved = json.loads(
        temporary_audit_file.read_text(
            encoding="utf-8"
        ).strip()
    )

    assert saved == event


def test_audit_excludes_sensitive_information(
    temporary_audit_file,
):
    audit_module.record_document_integrity_failure(
        request_id=str(uuid.uuid4()),
        route="/chat/rag",
    )

    serialized = temporary_audit_file.read_text(
        encoding="utf-8"
    )

    for forbidden in (
        "prompt",
        "policy_content",
        "document_text",
        "sha256",
        "file_path",
        "exception_message",
    ):
        assert forbidden not in serialized


def test_multiple_events_append(
    temporary_audit_file,
):
    for _ in range(3):
        audit_module.record_document_integrity_failure(
            request_id=str(uuid.uuid4()),
            route="/chat/rag",
        )

    lines = temporary_audit_file.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 3

    assert all(
        json.loads(line)["decision"] == "blocked"
        for line in lines
    )


@pytest.mark.parametrize(
    "route",
    [
        "/unknown",
        "/chat",
        "",
    ],
)
def test_invalid_route_rejected(
    temporary_audit_file,
    route,
):
    with pytest.raises(ValueError):
        audit_module.record_document_integrity_failure(
            request_id=str(uuid.uuid4()),
            route=route,
        )

    assert not temporary_audit_file.exists()


def test_invalid_request_id_rejected(
    temporary_audit_file,
):
    with pytest.raises(ValueError):
        audit_module.record_document_integrity_failure(
            request_id="invalid-request-id",
            route="/chat/rag",
        )

    assert not temporary_audit_file.exists()


def test_dependency_initialization_stage_supported(
    temporary_audit_file,
):
    event = audit_module.record_document_integrity_failure(
        request_id=str(uuid.uuid4()),
        route="/chat/rag",
        stage="dependency_initialization",
    )

    assert event["stage"] == (
        "dependency_initialization"
    )
