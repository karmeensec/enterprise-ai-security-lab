
import json

import pytest

import backend.audit_logger as audit_logger


@pytest.fixture
def isolated_audit_file(tmp_path, monkeypatch):
    """Keep test events out of the real audit log."""
    path = tmp_path / "security_audit.jsonl"

    monkeypatch.setattr(
        audit_logger,
        "AUDIT_DIRECTORY",
        tmp_path,
    )
    monkeypatch.setattr(
        audit_logger,
        "AUDIT_FILE",
        path,
    )

    return path


def record(**overrides):
    values = {
        "request_id": "test-123",
        "cited_document": "POL-005",
        "decision": "supported_by_checks",
        "review_required": False,
        "duration_ms": 125.5,
    }
    values.update(overrides)

    return audit_logger.record_security_evaluation(**values)


def test_successful_audit_record(isolated_audit_file):
    event = record()

    assert event["decision"] == "supported_by_checks"
    assert event["request_id"] == "test-123"
    assert isolated_audit_file.exists()

    saved = json.loads(
        isolated_audit_file.read_text(encoding="utf-8")
    )

    assert saved["request_id"] == "test-123"


def test_error_audit_record(isolated_audit_file):
    event = record(
        decision="evaluation_error",
        review_required=True,
    )

    assert event["decision"] == "evaluation_error"
    assert event["review_required"] is True


def test_invalid_decision_rejected(isolated_audit_file):
    with pytest.raises(ValueError):
        record(decision="allow_everything")

    assert not isolated_audit_file.exists()


def test_invalid_duration_rejected(isolated_audit_file):
    with pytest.raises(ValueError):
        record(duration_ms=-50)

    assert not isolated_audit_file.exists()


def test_sensitive_content_excluded(isolated_audit_file):
    sensitive_text = "PRIVATE_TEST_SECRET_98765"

    # Sensitive content should never appear in
    # the metadata fields we choose to persist.
    record()

    content = isolated_audit_file.read_text(
        encoding="utf-8"
    )

    assert sensitive_text not in content

    saved = json.loads(content)

    assert "claim" not in saved
    assert "prompt" not in saved
    assert "response" not in saved
    assert "policy_content" not in saved
