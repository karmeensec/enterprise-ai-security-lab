
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import backend.investigation_records as case_store
import backend.response_plan_store as plan_store
import dashboard.router as dashboard_module


USERNAME = "response-analyst"
PASSWORD = "test-password"


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
        tmp_path / "response_plans.jsonl",
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
    return (USERNAME, PASSWORD)


def headers():
    return {
        "X-Requested-With": "XMLHttpRequest",
        "Origin": "http://testserver",
    }


def make_case():
    return case_store.create_case(
        alert={
            "rule_id": "AI-MON-004",
            "request_ids": ["req-001"],
        },
        analyst=USERNAME,
        notes="Test investigation",
    )


def make_plan(client, case_id, action="disable_account"):
    return client.post(
        "/dashboard/response-plans",
        json={
            "case_id": case_id,
            "action": action,
            "target": "test-user",
        },
        headers=headers(),
        auth=auth(),
    )


def test_response_actions_require_authentication(client):
    response = client.get(
        "/dashboard/response-actions"
    )

    assert response.status_code == 401


def test_response_plan_requires_existing_case(client):
    response = make_plan(
        client,
        str(uuid4()),
    )

    assert response.status_code == 404


def test_create_response_plan_uses_trusted_case(client):
    case = make_case()

    response = make_plan(
        client,
        case["case_id"],
    )

    assert response.status_code == 201, response.text

    plan = response.json()

    assert plan["case_id"] == case["case_id"]
    assert plan["status"] == "pending_approval"
    assert plan["executed"] is False
    assert plan["execution_mode"] == "simulation_only"


def test_caller_cannot_forge_case_status(client):
    case = make_case()

    response = client.post(
        "/dashboard/response-plans",
        json={
            "case_id": case["case_id"],
            "case_status": "investigating",
            "action": "disable_account",
        },
        headers=headers(),
        auth=auth(),
    )

    assert response.status_code == 422


def test_response_plan_requires_write_headers(client):
    case = make_case()

    response = client.post(
        "/dashboard/response-plans",
        json={
            "case_id": case["case_id"],
            "action": "disable_account",
        },
        auth=auth(),
    )

    assert response.status_code == 403


def test_approval_is_authenticated_and_persisted(client):
    case = make_case()

    created = make_plan(
        client,
        case["case_id"],
    )

    plan_id = created.json()["plan_id"]

    reviewed = client.post(
        f"/dashboard/response-plans/{plan_id}/review",
        json={
            "decision": "approve",
            "notes": "Reviewed lab evidence",
        },
        headers=headers(),
        auth=auth(),
    )

    assert reviewed.status_code == 200, reviewed.text

    result = reviewed.json()

    assert result["status"] == "approved_for_simulation"
    assert result["approval"]["reviewer"] == USERNAME
    assert result["executed"] is False

    history = client.get(
        f"/dashboard/response-plans/{plan_id}",
        auth=auth(),
    )

    assert history.status_code == 200
    assert len(history.json()["history"]) == 2


def test_approval_requires_configured_approver(
    client,
    monkeypatch,
):
    case = make_case()

    created = make_plan(
        client,
        case["case_id"],
    )

    plan_id = created.json()["plan_id"]

    monkeypatch.setenv(
        "RESPONSE_APPROVER_USERS",
        "some-other-user",
    )

    response = client.post(
        f"/dashboard/response-plans/{plan_id}/review",
        json={
            "decision": "approve",
            "notes": "Attempted approval",
        },
        headers=headers(),
        auth=auth(),
    )

    assert response.status_code == 403


def test_resolved_case_cannot_create_response(client):
    case = make_case()

    case_store.update_case(
        case_id=case["case_id"],
        analyst=USERNAME,
        status="investigating",
        notes="Investigating",
    )

    case_store.update_case(
        case_id=case["case_id"],
        analyst=USERNAME,
        status="resolved",
        disposition="inconclusive",
        notes="Investigation complete",
    )

    response = make_plan(
        client,
        case["case_id"],
    )

    assert response.status_code == 409


def test_approval_never_executes_action(client):
    case = make_case()

    created = make_plan(
        client,
        case["case_id"],
        action="revoke_credentials",
    )

    plan_id = created.json()["plan_id"]

    response = client.post(
        f"/dashboard/response-plans/{plan_id}/review",
        json={
            "decision": "approve",
            "notes": "Approved simulation only",
        },
        headers=headers(),
        auth=auth(),
    )

    assert response.status_code == 200

    plan = response.json()

    assert plan["risk_level"] == "critical"
    assert plan["execution_mode"] == "simulation_only"
    assert plan["executed"] is False
