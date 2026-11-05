
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from backend.response_timeline import (
    ResponseTimelineError,
    build_response_timeline,
)


CASE_ID = str(uuid4())
OTHER_CASE_ID = str(uuid4())
PLAN_ID = str(uuid4())
SIMULATION_ID = str(uuid4())

BASE_TIME = datetime(
    2026, 11, 5, 12, 0, tzinfo=timezone.utc
)


def timestamp(minutes):
    return (
        BASE_TIME + timedelta(minutes=minutes)
    ).isoformat()


def plan_record(
    case_id=CASE_ID,
    plan_id=PLAN_ID,
    revision=1,
    event_type="plan_created",
    minutes=0,
):
    return {
        "event_type": event_type,
        "recorded_at": timestamp(minutes),
        "revision": revision,
        "plan": {
            "case_id": case_id,
            "plan_id": plan_id,
            "action": "disable_account",
            "status": (
                "pending_approval"
                if revision == 1
                else "approved_for_simulation"
            ),
            "target": "sensitive-account",
            "approval": {
                "notes": "Private analyst notes",
            },
        },
    }


def simulation_record(
    case_id=CASE_ID,
    plan_id=PLAN_ID,
    minutes=2,
):
    return {
        "simulation_id": SIMULATION_ID,
        "case_id": case_id,
        "plan_id": plan_id,
        "action": "disable_account",
        "simulation_status": "completed",
        "execution_mode": "simulation_only",
        "real_action_executed": False,
        "simulated_at": timestamp(minutes),
        "target": "sensitive-account",
        "summary": "Private simulation summary",
    }


def test_complete_response_timeline():
    plans = [
        plan_record(),
        plan_record(
            revision=2,
            event_type="plan_reviewed",
            minutes=1,
        ),
    ]

    simulations = [
        simulation_record()
    ]

    result = build_response_timeline(
        CASE_ID,
        plans,
        simulations,
    )

    assert result["event_count"] == 3
    assert result["plan_count"] == 1

    assert [
        item["event_type"]
        for item in result["events"]
    ] == [
        "plan_created",
        "plan_reviewed",
        "simulation_completed",
    ]


def test_other_case_records_are_excluded():
    result = build_response_timeline(
        CASE_ID,
        [
            plan_record(),
            plan_record(
                case_id=OTHER_CASE_ID,
                plan_id=str(uuid4()),
            ),
        ],
        [],
    )

    assert result["event_count"] == 1


def test_timeline_is_sorted_chronologically():
    plans = [
        plan_record(
            revision=2,
            event_type="plan_reviewed",
            minutes=4,
        ),
        plan_record(minutes=0),
    ]

    result = build_response_timeline(
        CASE_ID,
        plans,
        [
            simulation_record(minutes=6)
        ],
    )

    assert [
        item["event_type"]
        for item in result["events"]
    ] == [
        "plan_created",
        "plan_reviewed",
        "simulation_completed",
    ]


def test_sensitive_fields_are_not_exposed():
    result = build_response_timeline(
        CASE_ID,
        [plan_record()],
        [simulation_record()],
    )

    for event in result["events"]:
        assert "target" not in event
        assert "approval" not in event
        assert "notes" not in event
        assert "summary" not in event


def test_unknown_simulation_plan_is_rejected():
    simulation = simulation_record(
        plan_id=str(uuid4())
    )

    with pytest.raises(
        ResponseTimelineError,
        match="no matching response plan",
    ):
        build_response_timeline(
            CASE_ID,
            [plan_record()],
            [simulation],
        )


def test_real_execution_claim_is_rejected():
    simulation = simulation_record()
    simulation["real_action_executed"] = True

    with pytest.raises(
        ResponseTimelineError,
        match="Invalid simulation security state",
    ):
        build_response_timeline(
            CASE_ID,
            [plan_record()],
            [simulation],
        )


def test_naive_timestamp_is_rejected():
    plan = plan_record()
    plan["recorded_at"] = (
        "2026-11-05T12:00:00"
    )

    with pytest.raises(
        ResponseTimelineError,
        match="requires timezone",
    ):
        build_response_timeline(
            CASE_ID,
            [plan],
            [],
        )


def test_invalid_case_id_is_rejected():
    with pytest.raises(
        ResponseTimelineError,
        match="Invalid case ID",
    ):
        build_response_timeline(
            "not-a-uuid",
            [],
            [],
        )


def test_source_records_are_not_modified():
    plans = [plan_record()]
    simulations = [simulation_record()]

    original_plans = deepcopy(plans)
    original_simulations = deepcopy(simulations)

    build_response_timeline(
        CASE_ID,
        plans,
        simulations,
    )

    assert plans == original_plans
    assert simulations == original_simulations


def test_empty_timeline_is_supported():
    result = build_response_timeline(
        CASE_ID,
        [],
        [],
    )

    assert result["event_count"] == 0
    assert result["plan_count"] == 0
    assert result["events"] == []


def test_record_limit_is_enforced():
    records = [
        plan_record()
        for _ in range(1001)
    ]

    with pytest.raises(
        ResponseTimelineError,
        match="Too many timeline records",
    ):
        build_response_timeline(
            CASE_ID,
            records,
            [],
        )
