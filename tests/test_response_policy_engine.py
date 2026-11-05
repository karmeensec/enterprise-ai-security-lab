
from uuid import uuid4

import pytest

from backend.response_policy_engine import (
    ResponsePolicyError,
    create_response_plan,
    list_response_actions,
)


CASE_ID = str(uuid4())


def make_plan(
    action="review_audit_logs",
    status="investigating",
    target=None,
):
    return create_response_plan(
        case_id=CASE_ID,
        case_status=status,
        action=action,
        target=target,
    )


def test_low_risk_action_is_eligible():
    plan = make_plan()

    assert plan["policy_decision"] == (
        "eligible_for_simulation"
    )
    assert plan["status"] == "proposed"
    assert plan["requires_approval"] is False
    assert plan["executed"] is False


def test_high_risk_action_requires_approval():
    plan = make_plan(
        action="disable_account",
        target="test-user",
    )

    assert plan["requires_approval"] is True
    assert plan["risk_level"] == "high"
    assert plan["status"] == "pending_approval"
    assert plan["executed"] is False


def test_critical_action_requires_approval():
    plan = make_plan(
        action="revoke_credentials",
        target="test-account",
    )

    assert plan["risk_level"] == "critical"
    assert plan["policy_decision"] == (
        "approval_required"
    )


def test_resolved_case_cannot_create_response():
    with pytest.raises(
        ResponsePolicyError,
        match="open or investigating",
    ):
        make_plan(status="resolved")


def test_unsupported_action_is_rejected():
    with pytest.raises(
        ResponsePolicyError,
        match="Unsupported response action",
    ):
        make_plan(action="delete_everything")


def test_invalid_case_id_is_rejected():
    with pytest.raises(
        ResponsePolicyError,
        match="Case ID",
    ):
        create_response_plan(
            case_id="invalid",
            case_status="investigating",
            action="review_audit_logs",
        )


def test_response_plan_never_executes():
    for action in (
        "review_audit_logs",
        "isolate_service",
        "disable_account",
        "revoke_credentials",
        "restore_trusted_policies",
    ):
        plan = make_plan(action=action)

        assert plan["execution_mode"] == (
            "simulation_only"
        )
        assert plan["executed"] is False


def test_invalid_target_is_rejected():
    with pytest.raises(
        ResponsePolicyError,
        match="Invalid response target",
    ):
        make_plan(
            action="disable_account",
            target="",
        )


def test_response_catalog_contains_seven_actions():
    actions = list_response_actions()

    assert len(actions) == 7
    assert all(
        "risk_level" in action
        for action in actions
    )


def test_response_plans_have_unique_ids():
    first = make_plan()
    second = make_plan()

    assert first["plan_id"] != second["plan_id"]
