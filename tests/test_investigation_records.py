import json

import pytest

from backend.investigation_records import (
    create_case,
    load_case_history,
    load_cases,
    update_case,
)


@pytest.fixture
def case_file(tmp_path):
    return tmp_path / "cases.jsonl"


@pytest.fixture
def alert():
    return {
        "rule_id": "AI-MON-005",
        "request_ids": ["req-001", "req-002", "req-001"],
    }


def test_create_case_is_open_and_deduplicates_ids(alert, case_file):
    record = create_case(alert, analyst="analyst1", file_path=case_file)
    assert record["status"] == "open"
    assert record["disposition"] == "pending"
    assert record["request_ids"] == ["req-001", "req-002"]
    assert record["revision"] == 1
    assert load_cases(case_file) == [record]


def test_full_workflow_preserves_revision_history(alert, case_file):
    initial = create_case(alert, "analyst1", file_path=case_file)
    working = update_case(initial["case_id"], "analyst2", "investigating", notes="Checking deployment", file_path=case_file)
    closed = update_case(initial["case_id"], "analyst2", "resolved", "benign", "Approved config change", case_file)
    assert [item["revision"] for item in load_case_history(initial["case_id"], case_file)] == [1, 2, 3]
    assert load_cases(case_file) == [closed]
    assert working["status"] == "investigating"
    assert initial["status"] == "open"
    assert len(case_file.read_text(encoding="utf-8").splitlines()) == 3


def test_cannot_resolve_directly_from_open(alert, case_file):
    case = create_case(alert, "analyst1", file_path=case_file)
    with pytest.raises(ValueError, match="transition"):
        update_case(case["case_id"], "analyst1", "resolved", "confirmed_incident", file_path=case_file)
    assert len(load_case_history(case["case_id"], case_file)) == 1


def test_resolved_requires_final_disposition(alert, case_file):
    case = create_case(alert, "analyst1", file_path=case_file)
    update_case(case["case_id"], "analyst1", "investigating", file_path=case_file)
    with pytest.raises(ValueError, match="Disposition"):
        update_case(case["case_id"], "analyst1", "resolved", file_path=case_file)


def test_final_disposition_not_allowed_while_investigating(alert, case_file):
    case = create_case(alert, "analyst1", file_path=case_file)
    with pytest.raises(ValueError, match="Disposition"):
        update_case(case["case_id"], "analyst1", "investigating", "benign", file_path=case_file)


def test_resolved_case_cannot_be_changed(alert, case_file):
    case = create_case(alert, "analyst1", file_path=case_file)
    update_case(case["case_id"], "analyst1", "investigating", file_path=case_file)
    update_case(case["case_id"], "analyst1", "resolved", "inconclusive", file_path=case_file)
    with pytest.raises(ValueError, match="transition"):
        update_case(case["case_id"], "analyst1", "investigating", file_path=case_file)


def test_long_notes_rejected_without_writing(alert, case_file):
    with pytest.raises(ValueError, match="notes"):
        create_case(alert, "analyst1", "x" * 2001, file_path=case_file)
    assert not case_file.exists()


def test_invalid_alert_requests_rejected(case_file):
    with pytest.raises(ValueError, match="request IDs"):
        create_case({"rule_id": "AI-MON-005", "request_ids": []}, "analyst1", file_path=case_file)


def test_corrupt_history_fails_closed(alert, case_file):
    case_file.write_text("{broken json}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="history"):
        create_case(alert, "analyst1", file_path=case_file)
    assert case_file.read_text(encoding="utf-8") == "{broken json}\n"


def test_multiple_cases_keep_separate_histories(alert, case_file):
    first = create_case(alert, "analyst1", file_path=case_file)
    second = create_case(alert, "analyst2", file_path=case_file)
    update_case(first["case_id"], "analyst1", "investigating", file_path=case_file)
    assert len(load_cases(case_file)) == 2
    assert len(load_case_history(first["case_id"], case_file)) == 2
    assert len(load_case_history(second["case_id"], case_file)) == 1
