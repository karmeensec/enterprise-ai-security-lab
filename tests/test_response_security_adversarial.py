
"""
Experiment 50.8 — Adversarial Response Workflow Tests.

Verify that callers cannot bypass response approvals,
forge trusted state, or force real-world execution.

These tests use isolated local files.
"""

import json
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import backend.investigation_records as case_store
import backend.response_plan_store as plan_store
import backend.response_simulation_store as simulation_store
import dashboard.router as dashboard_module


USERNAME = "security-test-analyst"
PASSWORD = "local-test-password"


@pytest.fixture
def environment(tmp_path, monkeypatch):
    cases = tmp_path / "cases.jsonl"
    plans = tmp_path / "plans.jsonl"
    simulations = tmp_path / "simulations.jsonl"

    monkeypatch.setattr(
        case_store,
        "DEFAULT_CASE_FILE",
        cases,
    )

    monkeypatch.setattr(
        plan_store,
        "RESPONSE_PLAN_FILE",
        plans,
    )

    monkeypatch.setattr(
        simulation_store,
        "SIMULATION_FILE",
        simulations,
    )

    monkeypatch.setenv(
        "DASHBOARD_USERNAME",
        USERNAME,
    )

    monkeypatch.setenv(
        "DASHBOARD_PASSWORD",
        PASSWORD,
    )

    monkeypatch.setenv(
        "RESPONSE_APPROVER_USERS",
        USERNAME,
    )

    app = FastAPI()
    app.include_router(dashboard_module.router)

    with TestClient(app) as client:
        yield {
            "client": client,
            "monkeypatch": monkeypatch,
            "cases": cases,
            "plans": plans,
            "simulations": simulations,
        }


def auth():
    return USERNAME, PASSWORD


def headers(origin="http://testserver"):
    return {
        "X-Requested-With": "XMLHttpRequest",
        "Origin": origin,
    }


def create_case():
    return case_store.create_case(
        alert={
            "rule_id": "AI-MON-004",
            "request_ids": ["adversarial-test-request"],
        },
        analyst=USERNAME,
        notes="Controlled security evaluation",
    )


def create_plan(client, case_id, action):
    return client.post(
        "/dashboard/response-plans",
        json={
            "case_id": case_id,
            "action": action,
            "target": "test-resource",
        },
        auth=auth(),
        headers=headers(),
    )


def approve(client, plan_id):
    return client.post(
        f"/dashboard/response-plans/{plan_id}/review",
        json={
            "decision": "approve",
            "notes": "Approved controlled simulation",
        },
        auth=auth(),
        headers=headers(),
    )


def simulate(client, plan_id, payload=None, request_headers=None):
    return client.post(
        f"/dashboard/response-plans/{plan_id}/simulate",
        json={} if payload is None else payload,
        auth=auth(),
        headers=(
            headers()
            if request_headers is None
            else request_headers
        ),
    )


def test_forged_approval_cannot_bypass_review(environment):
    client = environment["client"]
    case = create_case()

    created = create_plan(
        client,
        case["case_id"],
        "disable_account",
    )

    assert created.status_code == 201

    plan_id = created.json()["plan_id"]

    response = simulate(
        client,
        plan_id,
        payload={
            "approved": True,
            "approval": {
                "decision": "approve",
                "reviewer": "fake-admin",
            },
            "execution_mode": "live",
        },
    )

    assert response.status_code == 409

    assert not environment["simulations"].exists()


def test_cross_origin_simulation_rejected(environment):
    client = environment["client"]
    case = create_case()

    created = create_plan(
        client,
        case["case_id"],
        "review_audit_logs",
    )

    assert created.status_code == 201

    response = simulate(
        client,
        created.json()["plan_id"],
        request_headers=headers(
            "https://untrusted.example"
        ),
    )

    assert response.status_code == 403
    assert not environment["simulations"].exists()


def test_unconfigured_approver_fails_closed(environment):
    client = environment["client"]
    case = create_case()

    created = create_plan(
        client,
        case["case_id"],
        "revoke_credentials",
    )

    assert created.status_code == 201

    environment["monkeypatch"].delenv(
        "RESPONSE_APPROVER_USERS",
        raising=False,
    )

    response = approve(
        client,
        created.json()["plan_id"],
    )

    assert response.status_code == 503

    stored = plan_store.get_stored_response_plan(
        created.json()["plan_id"]
    )

    assert stored["status"] == "pending_approval"


def test_unknown_action_cannot_create_plan(environment):
    client = environment["client"]
    case = create_case()

    response = create_plan(
        client,
        case["case_id"],
        "execute_arbitrary_command",
    )

    assert response.status_code == 422

    assert plan_store.list_stored_response_plans() == []


def test_caller_cannot_submit_fake_case(environment):
    client = environment["client"]

    response = create_plan(
        client,
        str(uuid4()),
        "disable_account",
    )

    assert response.status_code == 404
    assert plan_store.list_stored_response_plans() == []


def test_corrupted_simulation_history_blocks_execution(
    environment,
):
    client = environment["client"]
    case = create_case()

    created = create_plan(
        client,
        case["case_id"],
        "collect_evidence",
    )

    assert created.status_code == 201

    environment["simulations"].write_text(
        '{"invalid": true}\n',
        encoding="utf-8",
    )

    response = simulate(
        client,
        created.json()["plan_id"],
    )

    assert response.status_code == 503

    # The corrupted record should not be replaced
    # with a fabricated successful simulation.
    assert len(
        environment["simulations"].read_text(
            encoding="utf-8"
        ).splitlines()
    ) == 1


def test_approved_plan_remains_simulation_only(environment):
    client = environment["client"]
    case = create_case()

    created = create_plan(
        client,
        case["case_id"],
        "revoke_credentials",
    )

    assert created.status_code == 201

    plan_id = created.json()["plan_id"]

    reviewed = approve(client, plan_id)
    assert reviewed.status_code == 200

    result = simulate(client, plan_id)

    assert result.status_code == 201

    simulation = result.json()

    assert simulation["execution_mode"] == (
        "simulation_only"
    )
    assert simulation["real_action_executed"] is False

    assert all(
        value is False
        for value in simulation["safeguards"].values()
    )

    saved = simulation_store.get_stored_simulation(
        plan_id
    )

    assert saved == simulation


def test_duplicate_request_does_not_create_second_simulation(
    environment,
):
    client = environment["client"]
    case = create_case()

    created = create_plan(
        client,
        case["case_id"],
        "review_audit_logs",
    )

    assert created.status_code == 201

    plan_id = created.json()["plan_id"]

    first = simulate(client, plan_id)

    second = simulate(
        client,
        plan_id,
        payload={
            "force": True,
            "new_simulation": True,
        },
    )

    assert first.status_code == 201
    assert second.status_code == 409

    history = simulation_store.list_stored_simulations()

    assert len(history) == 1
    assert history[0]["plan_id"] == plan_id
