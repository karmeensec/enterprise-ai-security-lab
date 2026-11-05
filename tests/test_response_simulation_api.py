
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import backend.investigation_records as case_store
import backend.response_plan_store as plan_store
import backend.response_simulation_store as simulation_store
import dashboard.router as dashboard_module


USERNAME = "simulation-analyst"
PASSWORD = "simulation-test-password"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(
        case_store,
        "DEFAULT_CASE_FILE",
        tmp_path / "cases.jsonl",
    )

    monkeypatch.setattr(
        plan_store,
        "RESPONSE_PLAN_FILE",
        tmp_path / "plans.jsonl",
    )

    monkeypatch.setattr(
        simulation_store,
        "SIMULATION_FILE",
        tmp_path / "simulations.jsonl",
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

    with TestClient(app) as test_client:
        yield test_client


def auth():
    return USERNAME, PASSWORD


def headers():
    return {
        "X-Requested-With": "XMLHttpRequest",
        "Origin": "http://testserver",
    }


def create_case():
    return case_store.create_case(
        alert={
            "rule_id": "AI-MON-004",
            "request_ids": ["test-request-001"],
        },
        analyst=USERNAME,
        notes="Investigating policy integrity",
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


def review_plan(client, plan_id, decision="approve"):
    return client.post(
        f"/dashboard/response-plans/{plan_id}/review",
        json={
            "decision": decision,
            "notes": "Reviewed simulation proposal",
        },
        auth=auth(),
        headers=headers(),
    )


def simulate(client, plan_id, use_headers=True):
    return client.post(
        f"/dashboard/response-plans/{plan_id}/simulate",
        json={},
        auth=auth(),
        headers=headers() if use_headers else {},
    )


def test_simulation_requires_authentication(client):
    response = client.get(
        "/dashboard/simulations"
    )

    assert response.status_code == 401


def test_low_risk_simulation_via_api(client):
    case = create_case()

    created = create_plan(
        client,
        case["case_id"],
        "review_audit_logs",
    )
    assert created.status_code == 201, created.text

    plan = created.json()

    response = simulate(
        client,
        plan["plan_id"],
    )

    assert response.status_code == 201, response.text

    result = response.json()
    assert result["action"] == "review_audit_logs"
    assert result["real_action_executed"] is False
    assert result["execution_mode"] == "simulation_only"


def test_unapproved_high_risk_simulation_blocked(client):
    case = create_case()

    created = create_plan(
        client,
        case["case_id"],
        "disable_account",
    )

    response = simulate(
        client,
        created.json()["plan_id"],
    )

    assert response.status_code == 409

    history = client.get(
        "/dashboard/simulations",
        auth=auth(),
    )

    assert history.json()["count"] == 0


def test_approved_high_risk_simulation(client):
    case = create_case()

    created = create_plan(
        client,
        case["case_id"],
        "disable_account",
    )
    plan_id = created.json()["plan_id"]

    approved = review_plan(client, plan_id)

    assert approved.status_code == 200

    response = simulate(client, plan_id)

    assert response.status_code == 201, response.text
    assert response.json()["action"] == "disable_account"
    assert response.json()["real_action_executed"] is False


def test_rejected_plan_cannot_be_simulated(client):
    case = create_case()

    created = create_plan(
        client,
        case["case_id"],
        "revoke_credentials",
    )
    plan_id = created.json()["plan_id"]

    rejected = review_plan(
        client,
        plan_id,
        decision="reject",
    )
    assert rejected.status_code == 200

    response = simulate(client, plan_id)

    assert response.status_code == 409


def test_simulation_cannot_run_twice(client):
    case = create_case()

    created = create_plan(
        client,
        case["case_id"],
        "collect_evidence",
    )
    plan_id = created.json()["plan_id"]

    first = simulate(client, plan_id)
    second = simulate(client, plan_id)

    assert first.status_code == 201
    assert second.status_code == 409

    history = client.get(
        "/dashboard/simulations",
        auth=auth(),
    )

    assert history.json()["count"] == 1


def test_resolved_case_cannot_be_simulated(client):
    case = create_case()

    created = create_plan(
        client,
        case["case_id"],
        "review_audit_logs",
    )
    plan_id = created.json()["plan_id"]

    case_store.update_case(
        case_id=case["case_id"],
        analyst=USERNAME,
        status="investigating",
        notes="Review started",
    )

    case_store.update_case(
        case_id=case["case_id"],
        analyst=USERNAME,
        status="resolved",
        disposition="inconclusive",
        notes="Case closed",
    )

    response = simulate(client, plan_id)

    assert response.status_code == 409


def test_simulation_requires_write_verification(client):
    case = create_case()

    created = create_plan(
        client,
        case["case_id"],
        "review_audit_logs",
    )
    plan_id = created.json()["plan_id"]

    response = simulate(
        client,
        plan_id,
        use_headers=False,
    )

    assert response.status_code == 403


def test_simulation_history_can_be_retrieved(client):
    case = create_case()

    created = create_plan(
        client,
        case["case_id"],
        "verify_policy_integrity",
    )
    plan_id = created.json()["plan_id"]

    result = simulate(client, plan_id)

    assert result.status_code == 201

    response = client.get(
        f"/dashboard/simulations/{plan_id}",
        auth=auth(),
    )

    assert response.status_code == 200
    assert response.json()["plan_id"] == plan_id


def test_unknown_plan_is_rejected(client):
    response = simulate(
        client,
        str(uuid4()),
    )

    assert response.status_code == 404
