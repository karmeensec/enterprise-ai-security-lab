
import base64

import pytest
from fastapi.testclient import TestClient

import dashboard.router as dashboard_router
from backend.main import app


client = TestClient(app)

USERNAME = "test-console-admin"
PASSWORD = "test-console-password"

PAGES = [
    "/dashboard/",
    "/dashboard/monitoring",
    "/dashboard/rules",
    "/dashboard/events",
]


def auth_headers(username=USERNAME, password=PASSWORD):
    credentials = f"{username}:{password}"
    encoded = base64.b64encode(
        credentials.encode("utf-8")
    ).decode("ascii")

    return {"Authorization": f"Basic {encoded}"}


@pytest.fixture
def console_setup(monkeypatch):
    monkeypatch.setenv("DASHBOARD_USERNAME", USERNAME)
    monkeypatch.setenv("DASHBOARD_PASSWORD", PASSWORD)

    def fake_monitor(window_minutes=5):
        return {
            "monitoring_mode": "on_demand",
            "audit_file_exists": True,
            "valid_events_loaded": 12,
            "invalid_lines": 0,
            "monitoring": {
                "window_minutes": window_minutes,
                "events_in_window": 3,
                "alert_count": 1,
                "alerts": [
                    {
                        "rule_id": "AI-MON-001",
                        "rule_name": "Repeated AI evaluation failures",
                        "severity": "high",
                        "event_count": 3,
                        "threshold": 3,
                    }
                ],
            },
        }

    def fake_audit_events():
        return {
            "events": [
                {
                    "timestamp": "2026-10-28T12:00:00+00:00",
                    "event_type": "ai.security.evaluation",
                    "request_id": "test-event-001",
                    "cited_document": "POL-005",
                    "decision": "supported_by_checks",
                }
            ],
            "valid_events": 1,
            "invalid_lines": 0,
            "file_exists": True,
        }

    monkeypatch.setattr(
        dashboard_router,
        "run_live_monitor",
        fake_monitor,
    )

    monkeypatch.setattr(
        dashboard_router,
        "load_audit_events",
        fake_audit_events,
    )


@pytest.mark.parametrize("path", PAGES)
def test_all_pages_require_authentication(console_setup, path):
    response = client.get(path)

    assert response.status_code == 401


@pytest.mark.parametrize("path", PAGES)
def test_all_pages_reject_wrong_password(console_setup, path):
    response = client.get(
        path,
        headers=auth_headers(password="wrong"),
    )

    assert response.status_code == 401


@pytest.mark.parametrize("path", PAGES)
def test_all_pages_load_with_valid_credentials(console_setup, path):
    response = client.get(
        path,
        headers=auth_headers(),
    )

    assert response.status_code == 200
    assert "AI Security Console" in response.text


def test_overview_displays_monitoring_metrics(console_setup):
    response = client.get(
        "/dashboard/",
        headers=auth_headers(),
    )

    assert response.status_code == 200
    assert "Security Overview" in response.text
    assert "Total Audit Events" in response.text
    assert "Security Detection Findings" in response.text


def test_monitoring_page_displays_alert(console_setup):
    response = client.get(
        "/dashboard/monitoring",
        headers=auth_headers(),
    )

    assert response.status_code == 200
    assert "Repeated AI evaluation failures" in response.text
    assert "AI-MON-001" in response.text


def test_rules_page_displays_real_rules(console_setup):
    response = client.get(
        "/dashboard/rules",
        headers=auth_headers(),
    )

    assert response.status_code == 200

    for rule_id in (
        "AI-MON-001",
        "AI-MON-002",
        "AI-MON-003",
    ):
        assert rule_id in response.text


def test_audit_events_page_displays_history(console_setup):
    response = client.get(
        "/dashboard/events",
        headers=auth_headers(),
    )

    assert response.status_code == 200
    assert "test-event-001" in response.text
    assert "POL-005" in response.text
    assert "supported_by_checks" in response.text


def test_console_does_not_expose_password(console_setup):
    for path in PAGES:
        response = client.get(
            path,
            headers=auth_headers(),
        )

        assert response.status_code == 200
        assert PASSWORD not in response.text


def test_audit_events_failure_returns_503(
    console_setup,
    monkeypatch,
):
    def failing_reader():
        raise RuntimeError("Simulated audit read failure")

    monkeypatch.setattr(
        dashboard_router,
        "load_audit_events",
        failing_reader,
    )

    response = client.get(
        "/dashboard/events",
        headers=auth_headers(),
    )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "Audit history temporarily unavailable"
    )
