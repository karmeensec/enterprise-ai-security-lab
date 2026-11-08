
"""
Experiment 62 — API Boundary Security Tests.

These tests run locally using FastAPI TestClient.
No real Qwen inference, Docker writes, or response actions.
"""

import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import backend.agent_api as agent_api
from backend.agent_tool_security import (
    AgentSecurityContext,
    authorize_agent_tool_call,
)
from backend.secured_app import app


USERNAME = "security-test-analyst"
PASSWORD = "local-test-only-password"

client = TestClient(app)


@pytest.fixture(autouse=True)
def security_configuration(monkeypatch):
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


@pytest.fixture
def simulated_agent(monkeypatch):
    calls = []

    def fake_agent(question, context):
        calls.append({
            "question": question,
            "context": context,
        })

        return {
            "status": "completed",
            "allowed": True,
            "reason": None,
            "tool_name": "search_security_policies",
            "tool_result": {
                "documents": [],
                "count": 0,
            },
            "response_source": "authorized_tool_result",
            "real_action_executed": False,
        }

    monkeypatch.setattr(
        agent_api,
        "run_monitored_security_agent",
        fake_agent,
    )

    return calls


def credentials():
    return (USERNAME, PASSWORD)


def valid_headers():
    return {
        "X-Requested-With": "XMLHttpRequest",
    }


def post_chat(payload, *, auth=None, headers=None):
    return client.post(
        "/agent/chat",
        json=payload,
        auth=auth,
        headers=headers or {},
    )


def test_anonymous_agent_access_denied(simulated_agent):
    response = post_chat({
        "question": "Search VPN policy",
    })

    assert response.status_code == 401
    assert simulated_agent == []


def test_wrong_credentials_denied(simulated_agent):
    response = post_chat(
        {"question": "Search VPN policy"},
        auth=(USERNAME, "incorrect-password"),
        headers=valid_headers(),
    )

    assert response.status_code == 401
    assert simulated_agent == []


def test_valid_request_uses_server_identity(simulated_agent):
    response = post_chat(
        {"question": "Search VPN policy"},
        auth=credentials(),
        headers=valid_headers(),
    )

    assert response.status_code == 200
    assert len(simulated_agent) == 1

    context = simulated_agent[0]["context"]

    assert context.principal_id == USERNAME
    assert context.role == "analyst"
    assert context.authorized_case_ids == frozenset()
    assert response.json()["real_action_executed"] is False


@pytest.mark.parametrize(
    "extra",
    [
        {"role": "admin"},
        {"authorized_case_ids": [str(uuid4())]},
        {"tool_name": "execute_command"},
        {"real_action_executed": True},
    ],
)
def test_client_cannot_inject_execution_fields(
    simulated_agent,
    extra,
):
    response = post_chat(
        {
            "question": "Search VPN policy",
            **extra,
        },
        auth=credentials(),
        headers=valid_headers(),
    )

    assert response.status_code == 422
    assert simulated_agent == []


@pytest.mark.parametrize(
    "question",
    [
        "",
        "x" * 1001,
    ],
)
def test_invalid_question_rejected(
    simulated_agent,
    question,
):
    response = post_chat(
        {"question": question},
        auth=credentials(),
        headers=valid_headers(),
    )

    assert response.status_code == 422
    assert simulated_agent == []


def test_malformed_json_rejected(simulated_agent):
    response = client.post(
        "/agent/chat",
        content='{"question":',
        auth=credentials(),
        headers={
            **valid_headers(),
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 422
    assert simulated_agent == []


def test_missing_csrf_header_rejected(simulated_agent):
    response = post_chat(
        {"question": "Search VPN policy"},
        auth=credentials(),
    )

    assert response.status_code == 403
    assert simulated_agent == []


def test_cross_origin_request_rejected(simulated_agent):
    response = post_chat(
        {"question": "Search VPN policy"},
        auth=credentials(),
        headers={
            **valid_headers(),
            "Origin": "https://attacker.example",
        },
    )

    assert response.status_code == 403
    assert simulated_agent == []


def test_unregistered_tool_denied():
    context = AgentSecurityContext(
        principal_id=USERNAME,
        role="analyst",
        authorized_case_ids=frozenset(),
    )

    result = authorize_agent_tool_call(
        "execute_command",
        {"command": "whoami"},
        context,
    )

    assert result["allowed"] is False
    assert result["execution_permitted"] is False


def test_unauthorized_case_access_denied():
    context = AgentSecurityContext(
        principal_id=USERNAME,
        role="analyst",
        authorized_case_ids=frozenset(),
    )

    result = authorize_agent_tool_call(
        "get_incident_timeline",
        {"case_id": str(uuid4())},
        context,
    )

    assert result["allowed"] is False
    assert result["execution_permitted"] is False


def test_tool_cannot_override_trusted_context():
    context = AgentSecurityContext(
        principal_id=USERNAME,
        role="analyst",
        authorized_case_ids=frozenset(),
    )

    result = authorize_agent_tool_call(
        "search_security_policies",
        {
            "query": "VPN access",
            "role": "admin",
        },
        context,
    )

    assert result["allowed"] is False
    assert result["execution_permitted"] is False


def test_missing_permission_configuration_fails_closed(
    monkeypatch,
    simulated_agent,
):
    monkeypatch.delenv(
        "AGENT_CASE_ACCESS_JSON",
        raising=False,
    )

    response = post_chat(
        {"question": "Search VPN policy"},
        auth=credentials(),
        headers=valid_headers(),
    )

    assert response.status_code == 503
    assert simulated_agent == []


def test_internal_failure_does_not_leak_details(
    monkeypatch,
):
    private_path = "C:/private/secrets/key.txt"

    def failed_agent(question, context):
        raise RuntimeError(private_path)

    monkeypatch.setattr(
        agent_api,
        "run_monitored_security_agent",
        failed_agent,
    )

    response = post_chat(
        {"question": "Search VPN policy"},
        auth=credentials(),
        headers=valid_headers(),
    )

    assert response.status_code == 503
    assert private_path not in response.text
    assert PASSWORD not in response.text


def test_invalid_execution_state_fails_closed(
    monkeypatch,
):
    def unsafe_result(question, context):
        return {
            "status": "completed",
            "allowed": True,
            "real_action_executed": True,
        }

    monkeypatch.setattr(
        agent_api,
        "run_monitored_security_agent",
        unsafe_result,
    )

    response = post_chat(
        {"question": "Search VPN policy"},
        auth=credentials(),
        headers=valid_headers(),
    )

    assert response.status_code == 503


def test_agent_monitor_requires_authentication():
    response = client.get("/agent/monitor")

    assert response.status_code == 401


def test_agent_monitor_rejects_bad_window():
    response = client.get(
        "/agent/monitor?window_minutes=999",
        auth=credentials(),
    )

    assert response.status_code == 422


def test_agent_monitor_failure_sanitized(monkeypatch):
    def failed_monitor(window_minutes):
        raise RuntimeError("/private/audit/internal.jsonl")

    monkeypatch.setattr(
        agent_api,
        "run_agent_monitor",
        failed_monitor,
    )

    response = client.get(
        "/agent/monitor",
        auth=credentials(),
    )

    assert response.status_code == 503
    assert "/private/audit" not in response.text
