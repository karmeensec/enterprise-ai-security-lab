
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import backend.agent_dashboard as dashboard
from backend.secured_app import app


client = TestClient(app)

USERNAME = "exp58-analyst"
PASSWORD = "exp58-password"


@pytest.fixture(autouse=True)
def authentication(monkeypatch):
    monkeypatch.setenv(
        "DASHBOARD_USERNAME",
        USERNAME,
    )
    monkeypatch.setenv(
        "DASHBOARD_PASSWORD",
        PASSWORD,
    )


@pytest.fixture
def sample_monitor(monkeypatch):
    now = datetime.now(
        timezone.utc
    ).isoformat()

    principal = "a" * 24

    events = [
        {
            "timestamp": now,
            "event_type": (
                "ai.security.agent_tool_activity"
            ),
            "request_id": str(uuid4()),
            "principal_ref": principal,
            "tool_name": "get_incident_timeline",
            "decision": "blocked",
            "reason_category": "case_access_denied",
            "real_action_executed": False,
        }
    ]

    def fake_monitor(window_minutes=5):
        return {
            "audit_file_exists": True,
            "agent_events_loaded": 1,
            "invalid_lines": 0,
            "monitoring": {
                "alert_count": 1,
                "alerts": [
                    {
                        "rule_id": "AI-MON-007",
                        "rule_name": (
                            "Unauthorized incident case access"
                        ),
                        "severity": "high",
                        "principal_ref": principal,
                        "event_count": 1,
                        "threshold": 1,
                        "detected_at": now,
                    }
                ],
            },
        }

    def fake_loader():
        return {
            "events": events,
            "invalid_lines": 0,
            "file_exists": True,
        }

    monkeypatch.setattr(
        dashboard,
        "run_agent_monitor",
        fake_monitor,
    )

    monkeypatch.setattr(
        dashboard,
        "load_agent_events",
        fake_loader,
    )


def test_dashboard_requires_authentication():
    response = client.get(
        "/dashboard/agent-security"
    )

    assert response.status_code == 401


def test_authenticated_dashboard_renders(sample_monitor):
    response = client.get(
        "/dashboard/agent-security",
        auth=(USERNAME, PASSWORD),
    )

    assert response.status_code == 200
    assert "Agent Security Monitoring" in response.text


def test_detection_rule_visible(sample_monitor):
    response = client.get(
        "/dashboard/agent-security",
        auth=(USERNAME, PASSWORD),
    )

    assert response.status_code == 200
    assert "AI-MON-007" in response.text
    assert "Unauthorized incident case access" in response.text


def test_agent_activity_visible(sample_monitor):
    response = client.get(
        "/dashboard/agent-security",
        auth=(USERNAME, PASSWORD),
    )

    assert "get_incident_timeline" in response.text
    assert "BLOCKED" in response.text
    assert "case access denied" in response.text


def test_report_counts_are_correct(sample_monitor):
    report = dashboard.build_agent_dashboard_report()

    assert report["total_agent_events"] == 1
    assert report["recent_agent_events"] == 1
    assert report["alert_count"] == 1
    assert report["high_severity_count"] == 1


def test_dashboard_escapes_untrusted_text(
    sample_monitor,
    monkeypatch,
):
    original_loader = dashboard.load_agent_events

    def injected_loader():
        data = original_loader()
        data["events"][0]["tool_name"] = (
            "<script>alert(1)</script>"
        )
        return data

    monkeypatch.setattr(
        dashboard,
        "load_agent_events",
        injected_loader,
    )

    response = client.get(
        "/dashboard/agent-security",
        auth=(USERNAME, PASSWORD),
    )

    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_monitoring_failure_returns_503(monkeypatch):
    def fail(**kwargs):
        raise OSError(
            "C:/private/security_audit.jsonl"
        )

    monkeypatch.setattr(
        dashboard,
        "run_agent_monitor",
        fail,
    )

    response = client.get(
        "/dashboard/agent-security",
        auth=(USERNAME, PASSWORD),
    )

    assert response.status_code == 503
    assert "C:/private" not in response.text


def test_empty_agent_history(monkeypatch):
    monkeypatch.setattr(
        dashboard,
        "run_agent_monitor",
        lambda window_minutes=5: {
            "monitoring": {
                "alerts": [],
            },
        },
    )

    monkeypatch.setattr(
        dashboard,
        "load_agent_events",
        lambda: {
            "events": [],
            "invalid_lines": 0,
        },
    )

    response = client.get(
        "/dashboard/agent-security",
        auth=(USERNAME, PASSWORD),
    )

    assert response.status_code == 200
    assert "No active agent security alerts" in response.text
    assert "No agent audit events recorded" in response.text
