
from copy import deepcopy
from uuid import uuid4

import pytest

from backend.response_approval import (
    ResponseApprovalError,
    review_response_plan,
)
from backend.response_policy_engine import (
    create_response_plan,
)


CASE_ID = str(uuid4())


def make_plan(action="disable_account"):
    return create_response_plan(
        case_id=CASE_ID,
        case_status="investigating",
        action=action,
        target="test-account",
    )


def review(
    plan,
    decision="approve",
    reviewer="security-analyst",
    notes="Reviewed the proposed response action",
):
    return review_response_plan(
        plan=plan,
        reviewer=reviewer,
        decision=decision,
        notes=notes,
    )


def test_high_risk_plan_can_be_approved():
    plan = make_plan()

    result = review(plan)

    assert result["status"] == (
        "approved_for_simulation"
    )
    assert result["approval"]["decision"] == (
        "approve"
    )
    assert result["executed"] is False


def test_critical_plan_can_be_approved():
    plan = make_plan("revoke_credentials")

    result = review(plan)

    assert result["status"] == (
        "approved_for_simulation"
    )
    assert result["risk_level"] == "critical"
    assert result["executed"] is False


def test_plan_can_be_rejected():
    plan = make_plan()

    result = review(
        plan,
        decision="reject",
        notes="Insufficient supporting evidence",
    )

    assert result["status"] == "rejected"
    assert result["approval"]["decision"] == (
        "reject"
    )


def test_approval_does_not_modify_original():
    plan = make_plan()
    original = deepcopy(plan)

    review(plan)

    assert plan == original
    assert plan["status"] == "pending_approval"


def test_low_risk_action_cannot_be_approved():
    plan = make_plan("review_audit_logs")

    with pytest.raises(
        ResponseApprovalError,
        match="does not require approval",
    ):
        review(plan)


def test_approved_plan_cannot_be_approved_again():
    approved = review(make_plan())

    with pytest.raises(
        ResponseApprovalError,
        match="not pending approval",
    ):
        review(approved)


def test_rejected_plan_cannot_be_approved():
    rejected = review(
        make_plan(),
        decision="reject",
    )

    with pytest.raises(
        ResponseApprovalError,
        match="not pending approval",
    ):
        review(rejected)


def test_invalid_decision_is_rejected():
    with pytest.raises(
        ResponseApprovalError,
        match="approve or reject",
    ):
        review(
            make_plan(),
            decision="override",
        )


def test_empty_reviewer_is_rejected():
    with pytest.raises(
        ResponseApprovalError,
        match="Invalid reviewer",
    ):
        review(
            make_plan(),
            reviewer="",
        )


def test_empty_notes_are_rejected():
    with pytest.raises(
        ResponseApprovalError,
        match="Invalid approval notes",
    ):
        review(
            make_plan(),
            notes="",
        )


def test_executed_plan_cannot_be_approved():
    plan = make_plan()
    plan["executed"] = True

    with pytest.raises(
        ResponseApprovalError,
        match="Invalid response plan security state",
    ):
        review(plan)


def test_non_simulation_plan_is_rejected():
    plan = make_plan()
    plan["execution_mode"] = "live"

    with pytest.raises(
        ResponseApprovalError,
        match="Invalid response plan security state",
    ):
        review(plan)


def test_tampered_risk_level_is_rejected():
    plan = make_plan()
    plan["risk_level"] = "low"

    with pytest.raises(
        ResponseApprovalError,
        match="Invalid response plan security state",
    ):
        review(plan)
