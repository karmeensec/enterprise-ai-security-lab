
import json
from uuid import uuid4

import pytest

from backend.response_plan_store import (
    create_stored_response_plan,
    review_stored_response_plan,
)
from backend.response_simulation_store import (
    SimulationStoreError,
    simulate_stored_response_plan,
)
from backend.response_timeline import (
    ResponseTimelineError,
)
from backend.response_timeline_service import (
    load_response_timeline,
)


@pytest.fixture
def files(tmp_path):
    return {
        "plans": tmp_path / "plans.jsonl",
        "simulations": tmp_path / "simulations.jsonl",
        "case_id": str(uuid4()),
        "other_case_id": str(uuid4()),
    }


def make_plan(
    files,
    action="disable_account",
    case_id=None,
):
    return create_stored_response_plan(
        case_id=case_id or files["case_id"],
        case_status="investigating",
        action=action,
        target="test-resource",
        file_path=files["plans"],
    )


def approve(files, plan_id):
    return review_stored_response_plan(
        plan_id=plan_id,
        reviewer="authorized-analyst",
        decision="approve",
        notes="Approved for simulated response",
        file_path=files["plans"],
    )


def simulate(files, plan_id):
    return simulate_stored_response_plan(
        plan_id=plan_id,
        plan_file=files["plans"],
        simulation_file=files["simulations"],
    )


def timeline(files, case_id=None):
    return load_response_timeline(
        case_id=case_id or files["case_id"],
        plan_file=files["plans"],
        simulation_file=files["simulations"],
    )


def test_empty_storage_returns_empty_timeline(files):
    result = timeline(files)

    assert result["event_count"] == 0
    assert result["plan_count"] == 0
    assert result["events"] == []
    assert result["read_only"] is True


def test_created_plan_appears_in_timeline(files):
    plan = make_plan(files)

    result = timeline(files)

    assert result["event_count"] == 1
    assert result["plan_count"] == 1
    assert result["events"][0]["plan_id"] == (
        plan["plan_id"]
    )
    assert result["events"][0]["event_type"] == (
        "plan_created"
    )


def test_approval_history_is_preserved(files):
    plan = make_plan(files)
    approve(files, plan["plan_id"])

    result = timeline(files)

    assert result["event_count"] == 2

    assert {
        event["event_type"]
        for event in result["events"]
    } == {
        "plan_created",
        "plan_reviewed",
    }

    revisions = {
        event["revision"]
        for event in result["events"]
    }

    assert revisions == {1, 2}


def test_simulation_appears_in_timeline(files):
    plan = make_plan(files)

    approve(files, plan["plan_id"])
    simulate(files, plan["plan_id"])

    result = timeline(files)

    assert result["event_count"] == 3

    simulation_events = [
        event
        for event in result["events"]
        if event["event_type"]
        == "simulation_completed"
    ]

    assert len(simulation_events) == 1

    assert (
        simulation_events[0]["real_action_executed"]
        is False
    )


def test_low_risk_simulation_requires_no_approval(
    files,
):
    plan = make_plan(
        files,
        action="review_audit_logs",
    )

    simulate(files, plan["plan_id"])

    result = timeline(files)

    assert result["event_count"] == 2

    assert {
        item["event_type"]
        for item in result["events"]
    } == {
        "plan_created",
        "simulation_completed",
    }


def test_other_case_activity_is_excluded(files):
    first = make_plan(files)

    other = make_plan(
        files,
        action="review_audit_logs",
        case_id=files["other_case_id"],
    )

    simulate(files, other["plan_id"])

    result = timeline(files)

    assert result["plan_count"] == 1
    assert result["event_count"] == 1
    assert result["events"][0]["plan_id"] == (
        first["plan_id"]
    )


def test_multiple_plans_correlate_to_same_case(files):
    first = make_plan(
        files,
        action="review_audit_logs",
    )

    second = make_plan(
        files,
        action="disable_account",
    )

    approve(files, second["plan_id"])
    simulate(files, first["plan_id"])

    result = timeline(files)

    assert result["plan_count"] == 2
    assert result["event_count"] == 4


def test_timeline_omits_sensitive_details(files):
    plan = make_plan(files)

    approve(files, plan["plan_id"])

    result = timeline(files)

    serialized = json.dumps(result)

    assert "test-resource" not in serialized
    assert "Approved for simulated response" not in serialized
    assert "authorized-analyst" not in serialized


def test_corrupted_plan_history_fails_closed(files):
    make_plan(files)

    with files["plans"].open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write('{"invalid": true}\n')

    with pytest.raises(ValueError):
        timeline(files)


def test_corrupted_simulation_history_fails_closed(
    files,
):
    make_plan(files)

    files["simulations"].write_text(
        '{"invalid": true}\n',
        encoding="utf-8",
    )

    with pytest.raises(SimulationStoreError):
        timeline(files)


def test_invalid_case_id_is_rejected(files):
    with pytest.raises(
        ResponseTimelineError,
        match="Invalid case ID",
    ):
        timeline(files, case_id="invalid-id")


def test_timeline_does_not_modify_storage(files):
    plan = make_plan(files)

    approve(files, plan["plan_id"])
    simulate(files, plan["plan_id"])

    plan_before = files["plans"].read_bytes()
    simulations_before = (
        files["simulations"].read_bytes()
    )

    timeline(files)

    assert files["plans"].read_bytes() == (
        plan_before
    )
    assert files["simulations"].read_bytes() == (
        simulations_before
    )
