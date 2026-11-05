
import json
from uuid import uuid4

import pytest

from backend.response_plan_store import (
    create_stored_response_plan,
    review_stored_response_plan,
)
from backend.response_simulation_store import (
    SimulationStoreError,
    get_stored_simulation,
    list_stored_simulations,
    simulate_stored_response_plan,
)
from backend.response_simulator import (
    ResponseSimulationError,
)


CASE_ID = str(uuid4())


@pytest.fixture
def files(tmp_path):
    return {
        "plans": tmp_path / "response_plans.jsonl",
        "simulations": tmp_path / "simulations.jsonl",
    }


def create_plan(
    files,
    action="review_audit_logs",
):
    return create_stored_response_plan(
        case_id=CASE_ID,
        case_status="investigating",
        action=action,
        target="test-resource",
        file_path=files["plans"],
    )


def approve_plan(files, plan_id):
    return review_stored_response_plan(
        plan_id=plan_id,
        reviewer="authorized-analyst",
        decision="approve",
        notes="Approved for simulation",
        file_path=files["plans"],
    )


def run_simulation(files, plan_id):
    return simulate_stored_response_plan(
        plan_id=plan_id,
        simulation_file=files["simulations"],
        plan_file=files["plans"],
    )


def test_low_risk_simulation_is_persisted(files):
    plan = create_plan(files)

    result = run_simulation(
        files,
        plan["plan_id"],
    )

    assert result["simulation_status"] == "completed"
    assert result["real_action_executed"] is False

    assert files["simulations"].exists()


def test_high_risk_requires_approval(files):
    plan = create_plan(
        files,
        action="disable_account",
    )

    with pytest.raises(
        ResponseSimulationError,
        match="Approved response plan required",
    ):
        run_simulation(files, plan["plan_id"])

    assert not files["simulations"].exists()


def test_approved_high_risk_can_be_simulated(files):
    plan = create_plan(
        files,
        action="disable_account",
    )

    approve_plan(
        files,
        plan["plan_id"],
    )

    result = run_simulation(
        files,
        plan["plan_id"],
    )

    assert result["action"] == "disable_account"
    assert result["real_action_executed"] is False


def test_approved_critical_can_be_simulated(files):
    plan = create_plan(
        files,
        action="revoke_credentials",
    )

    approve_plan(
        files,
        plan["plan_id"],
    )

    result = run_simulation(
        files,
        plan["plan_id"],
    )

    assert result["risk_level"] == "critical"
    assert result["execution_mode"] == (
        "simulation_only"
    )


def test_duplicate_simulation_rejected(files):
    plan = create_plan(files)

    run_simulation(
        files,
        plan["plan_id"],
    )

    with pytest.raises(
        SimulationStoreError,
        match="already been simulated",
    ):
        run_simulation(
            files,
            plan["plan_id"],
        )

    history = list_stored_simulations(
        files["simulations"]
    )

    assert len(history) == 1


def test_simulation_can_be_retrieved(files):
    plan = create_plan(files)

    original = run_simulation(
        files,
        plan["plan_id"],
    )

    loaded = get_stored_simulation(
        plan["plan_id"],
        files["simulations"],
    )

    assert loaded == original


def test_multiple_plans_have_independent_records(files):
    first = create_plan(files)
    second = create_plan(
        files,
        action="collect_evidence",
    )

    run_simulation(
        files,
        first["plan_id"],
    )

    run_simulation(
        files,
        second["plan_id"],
    )

    history = list_stored_simulations(
        files["simulations"]
    )

    assert len(history) == 2
    assert len({
        item["simulation_id"]
        for item in history
    }) == 2


def test_unknown_plan_rejected(files):
    with pytest.raises(ValueError):
        run_simulation(
            files,
            str(uuid4()),
        )


def test_corrupt_simulation_history_fails_closed(files):
    files["simulations"].write_text(
        '{"invalid":true}\n',
        encoding="utf-8",
    )

    plan = create_plan(files)

    with pytest.raises(
        SimulationStoreError,
    ):
        run_simulation(
            files,
            plan["plan_id"],
        )


def test_duplicate_records_are_detected(files):
    plan = create_plan(files)

    result = run_simulation(
        files,
        plan["plan_id"],
    )

    with files["simulations"].open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(result) + "\n"
        )

    with pytest.raises(
        SimulationStoreError,
        match="Duplicate simulation",
    ):
        list_stored_simulations(
            files["simulations"]
        )


def test_simulation_records_never_claim_real_execution(files):
    plan = create_plan(
        files,
        action="revoke_credentials",
    )

    approve_plan(
        files,
        plan["plan_id"],
    )

    result = run_simulation(
        files,
        plan["plan_id"],
    )

    assert result["real_action_executed"] is False

    assert all(
        value is False
        for value in result["safeguards"].values()
    )
