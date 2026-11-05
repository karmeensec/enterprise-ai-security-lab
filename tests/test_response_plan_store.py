
import json
from uuid import uuid4

import pytest

from backend.response_approval import (
    ResponseApprovalError,
)
from backend.response_plan_store import (
    ResponseStoreError,
    create_stored_response_plan,
    get_response_plan_history,
    get_stored_response_plan,
    list_stored_response_plans,
    review_stored_response_plan,
)


CASE_ID = str(uuid4())


@pytest.fixture
def store(tmp_path):
    return tmp_path / "response_plans.jsonl"


def create(
    store,
    action="disable_account",
    status="investigating",
):
    return create_stored_response_plan(
        case_id=CASE_ID,
        case_status=status,
        action=action,
        target="test-account",
        file_path=store,
    )


def review(
    store,
    plan_id,
    decision="approve",
):
    return review_stored_response_plan(
        plan_id=plan_id,
        reviewer="security-analyst",
        decision=decision,
        notes="Reviewed supporting evidence",
        file_path=store,
    )


def test_create_plan_persists_to_disk(store):
    plan = create(store)

    assert store.exists()

    loaded = get_stored_response_plan(
        plan["plan_id"],
        file_path=store,
    )

    assert loaded == plan
    assert loaded["status"] == "pending_approval"


def test_low_risk_plan_is_proposed(store):
    plan = create(
        store,
        action="review_audit_logs",
    )

    assert plan["status"] == "proposed"
    assert plan["requires_approval"] is False
    assert plan["executed"] is False


def test_approval_preserves_original_revision(store):
    plan = create(store)
    approved = review(store, plan["plan_id"])

    history = get_response_plan_history(
        plan["plan_id"],
        file_path=store,
    )

    assert len(history) == 2
    assert history[0]["revision"] == 1
    assert history[1]["revision"] == 2

    assert history[0]["plan"]["status"] == (
        "pending_approval"
    )

    assert history[1]["plan"]["status"] == (
        "approved_for_simulation"
    )

    assert approved["executed"] is False


def test_rejection_is_persisted(store):
    plan = create(store)

    rejected = review(
        store,
        plan["plan_id"],
        decision="reject",
    )

    assert rejected["status"] == "rejected"

    latest = get_stored_response_plan(
        plan["plan_id"],
        file_path=store,
    )

    assert latest["approval"]["decision"] == (
        "reject"
    )


def test_plan_cannot_be_approved_twice(store):
    plan = create(store)

    review(store, plan["plan_id"])

    with pytest.raises(
        ResponseApprovalError,
        match="not pending approval",
    ):
        review(store, plan["plan_id"])

    history = get_response_plan_history(
        plan["plan_id"],
        file_path=store,
    )

    assert len(history) == 2


def test_multiple_plans_are_independent(store):
    first = create(store)
    second = create(
        store,
        action="revoke_credentials",
    )

    review(store, first["plan_id"])

    plans = list_stored_response_plans(
        file_path=store,
    )

    assert len(plans) == 2

    by_id = {
        plan["plan_id"]: plan
        for plan in plans
    }

    assert by_id[first["plan_id"]]["status"] == (
        "approved_for_simulation"
    )

    assert by_id[second["plan_id"]]["status"] == (
        "pending_approval"
    )


def test_unknown_plan_is_rejected(store):
    with pytest.raises(
        ResponseStoreError,
        match="not found",
    ):
        get_stored_response_plan(
            str(uuid4()),
            file_path=store,
        )


def test_corrupt_store_fails_closed(store):
    store.write_text(
        '{"invalid": true}\n',
        encoding="utf-8",
    )

    with pytest.raises(
        ResponseStoreError
    ):
        create(store)

    with pytest.raises(
        ResponseStoreError
    ):
        list_stored_response_plans(
            file_path=store,
        )


def test_revision_history_cannot_be_skipped(store):
    plan = create(store)

    fake_record = {
        "event_type": "plan_reviewed",
        "recorded_at": (
            "2026-11-04T18:00:00+00:00"
        ),
        "revision": 5,
        "plan": plan,
    }

    with store.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(fake_record) + "\n"
        )

    with pytest.raises(
        ResponseStoreError,
        match="Inconsistent",
    ):
        get_stored_response_plan(
            plan["plan_id"],
            file_path=store,
        )


def test_invalid_case_status_rejected(store):
    with pytest.raises(
        ValueError,
        match="open or investigating",
    ):
        create(
            store,
            status="resolved",
        )

    assert not store.exists()


def test_review_never_executes_action(store):
    plan = create(store)

    approved = review(
        store,
        plan["plan_id"],
    )

    assert approved["executed"] is False
    assert approved["execution_mode"] == (
        "simulation_only"
    )

    assert approved["status"] == (
        "approved_for_simulation"
    )
