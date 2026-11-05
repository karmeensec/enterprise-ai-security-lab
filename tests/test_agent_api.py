
import base64
import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import backend.agent_api as agent_api
from backend.secured_app import app


client = TestClient(app)

USERNAME = "exp57-analyst"
PASSWORD = "test-password"


def auth_headers():
    credentials = base64.b64encode(
        f"{USERNAME}:{PASSWORD}".encode()
    ).decode()

    return {
        "Authorization": f"Basic {credentials}",
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/json",
    }


@pytest.fixture(autouse=True)
def configured_auth(monkeypatch):
    monkeypatch.setenv(
        "DASHBOARD_USERNAME",
        USERNAME,
    )

    monkeypatch.setenv(
        "DASHBOARD_PASSWORD",
        PASSWORD,
    )

    monkeypatch.setenv(
        "AGENT_CASE_ACCESS_JSON",
        json.dumps({USERNAME: []}),
    )



def test_agent_routes_registered():
    """
    Verify agent routes through actual HTTP requests,
    not FastAPI's internal router representation.

    Both endpoints must exist and require authentication.
    """

    chat_response = client.post(
        "/agent/chat",
        json={"question": "Find VPN policy"},
    )

    monitor_response = client.get(
        "/agent/monitor"
    )

    assert chat_response.status_code == 401
    assert monitor_response.status_code == 401



def test_agent_requires_authentication():
    response = client.post(
        "/agent/chat",
        json={"question": "Find VPN policy"},
    )

    assert response.status_code == 401


def test_valid_analyst_request(monkeypatch):
    seen = []

    def fake_agent(question, context):
        seen.append({
            "question": question,
            "principal": context.principal_id,
            "role": context.role,
            "case_ids": context.authorized_case_ids,
        })

        return {
            "status": "completed",
            "allowed": True,
            "tool_name": "search_security_policies",
            "tool_result": {
                "documents": [],
                "count": 0,
            },
            "real_action_executed": False,
        }

    monkeypatch.setattr(
        agent_api,
        "run_monitored_security_agent",
        fake_agent,
    )

    response = client.post(
        "/agent/chat",
        json={"question": "Find VPN policy"},
        headers=auth_headers(),
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is True
    assert response.json()["real_action_executed"] is False

    assert len(seen) == 1
    assert seen[0]["principal"] == USERNAME
    assert seen[0]["role"] == "analyst"
    assert seen[0]["case_ids"] == frozenset()


def test_cannot_forge_admin_role():
    response = client.post(
        "/agent/chat",
        json={
            "question": "Find VPN policy",
            "role": "admin",
        },
        headers=auth_headers(),
    )

    assert response.status_code == 422


def test_cannot_supply_case_permissions():
    response = client.post(
        "/agent/chat",
        json={
            "question": "Find VPN policy",
            "authorized_case_ids": [str(uuid4())],
        },
        headers=auth_headers(),
    )

    assert response.status_code == 422


def test_missing_permissions_configuration(monkeypatch):
    monkeypatch.delenv(
        "AGENT_CASE_ACCESS_JSON",
    )

    response = client.post(
        "/agent/chat",
        json={"question": "Find VPN policy"},
        headers=auth_headers(),
    )

    assert response.status_code == 503


def test_unconfigured_analyst_denied(monkeypatch):
    monkeypatch.setenv(
        "AGENT_CASE_ACCESS_JSON",
        json.dumps({"another-user": []}),
    )

    response = client.post(
        "/agent/chat",
        json={"question": "Find VPN policy"},
        headers=auth_headers(),
    )

    assert response.status_code == 403


def test_authorized_case_list_server_controlled(
    monkeypatch,
):
    case_id = str(uuid4())

    monkeypatch.setenv(
        "AGENT_CASE_ACCESS_JSON",
        json.dumps({
            USERNAME: [case_id]
        }),
    )

    context = agent_api._trusted_agent_context(
        USERNAME
    )

    assert context.role == "analyst"
    assert context.authorized_case_ids == frozenset({
        case_id
    })


def test_missing_write_protection_header():
    headers = auth_headers()
    headers.pop("X-Requested-With")

    response = client.post(
        "/agent/chat",
        json={"question": "Find VPN policy"},
        headers=headers,
    )

    assert response.status_code == 403


def test_audit_failure_fails_closed(monkeypatch):
    def failed_agent(question, context):
        raise OSError(
            "C:/private/audit-log/secrets"
        )

    monkeypatch.setattr(
        agent_api,
        "run_monitored_security_agent",
        failed_agent,
    )

    response = client.post(
        "/agent/chat",
        json={"question": "Find VPN policy"},
        headers=auth_headers(),
    )

    assert response.status_code == 503
    assert "C:/private" not in response.text


def test_monitor_requires_authentication():
    response = client.get(
        "/agent/monitor"
    )

    assert response.status_code == 401


def test_authenticated_monitor(monkeypatch):
    def fake_monitor(window_minutes):
        return {
            "agent_events_loaded": 3,
            "monitoring": {
                "alert_count": 2,
                "alerts": [
                    {"rule_id": "AI-MON-006"},
                    {"rule_id": "AI-MON-007"},
                ],
            },
        }

    monkeypatch.setattr(
        agent_api,
        "run_agent_monitor",
        fake_monitor,
    )

    response = client.get(
        "/agent/monitor",
        headers=auth_headers(),
    )

    assert response.status_code == 200
    assert response.json()["monitoring"]["alert_count"] == 2


def test_invalid_monitor_window():
    response = client.get(
        "/agent/monitor?window_minutes=100",
        headers=auth_headers(),
    )

    assert response.status_code == 422
