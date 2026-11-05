
from copy import deepcopy
from uuid import uuid4

import pytest

from backend.response_policy_engine import (
    create_response_plan,
)
from backend.response_approval import (
    review_response_plan,
)
from backend.response_simulator import (
    ResponseSimulationError,
    simulate_response_plan,
)


CASE_ID = str(uuid4())


def make_plan(action="review_audit_logs"):
    return create_response_plan(
        case_id=CASE_ID,
        case_status="investigating",
        action=action,
        target="test-resource",
    )


def approved_plan(action="disable_account"):
    plan = make_plan(action)

    return review_response_plan(
        plan=plan,
        reviewer="security-analyst",
        decision="approve",
        notes="Approved for controlled simulation",
    )


def test_low_risk_simulation_completes():
    result = simulate_response_plan(
        make_plan()
    )

    assert result["simulation_status"] == "completed"
    assert result["real_action_executed"] is False


def test_approved_high_risk_simulation_completes():
    result = simulate_response_plan(
        approved_plan()
    )

    assert result["action"] == "disable_account"
    assert result["risk_level"] == "high"
    assert result["real_action_executed"] is False


def test_approved_critical_simulation_completes():
    result = simulate_response_plan(
        approved_plan("revoke_credentials")
    )

    assert result["risk_level"] == "critical"
    assert result["execution_mode"] == "simulation_only"


def test_unapproved_high_risk_plan_is_rejected():
    with pytest.raises(
        ResponseSimulationError,
        match="Approved response plan required",
    ):
        simulate_response_plan(
            make_plan("disable_account")
        )


def test_rejected_plan_cannot_be_simulated():
    plan = make_plan("disable_account")

    rejected = review_response_plan(
        plan=plan,
        reviewer="security-analyst",
        decision="reject",
        notes="Insufficient evidence",
    )

    with pytest.raises(
        ResponseSimulationError,
        match="Approved response plan required",
    ):
        simulate_response_plan(rejected)


def test_tampered_risk_level_is_rejected():
    plan = approved_plan()
    plan["risk_level"] = "low"

    with pytest.raises(
        ResponseSimulationError,
        match="Response policy mismatch",
    ):
        simulate_response_plan(plan)


def test_live_execution_mode_is_rejected():
    plan = approved_plan()
    plan["execution_mode"] = "live"

    with pytest.raises(
        ResponseSimulationError,
        match="Invalid simulation security state",
    ):
        simulate_response_plan(plan)


def test_missing_approval_record_is_rejected():
    plan = approved_plan()
    plan.pop("approval")

    with pytest.raises(
        ResponseSimulationError,
        match="Valid approval record required",
    ):
        simulate_response_plan(plan)


def test_unknown_action_is_rejected():
    plan = make_plan()
    plan["action"] = "delete_database"

    with pytest.raises(
        ResponseSimulationError,
        match="Unsupported response action",
    ):
        simulate_response_plan(plan)


def test_original_plan_is_not_modified():
    plan = approved_plan()
    original = deepcopy(plan)

    simulate_response_plan(plan)

    assert plan == original


def test_simulations_have_unique_ids():
    plan = approved_plan()

    first = simulate_response_plan(plan)
    second = simulate_response_plan(plan)

    assert first["simulation_id"] != second["simulation_id"]


def test_simulation_never_modifies_real_systems():
    for action in (
        "review_audit_logs",
        "verify_policy_integrity",
        "collect_evidence",
        "isolate_service",
        "disable_account",
        "revoke_credentials",
        "restore_trusted_policies",
    ):
        plan = make_plan(action)

        if plan["requires_approval"]:
            plan = review_response_plan(
                plan=plan,
                reviewer="security-analyst",
                decision="approve",
                notes="Authorized simulation",
            )

        result = simulate_response_plan(plan)

        assert result["real_action_executed"] is False

        assert all(
            value is False
            for value in result["safeguards"].values()
        )
