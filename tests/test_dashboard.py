
import base64

from fastapi.testclient import TestClient

import dashboard.router as dashboard_router
from backend.main import app


client = TestClient(app)

TEST_USERNAME = "test-security-admin"
TEST_PASSWORD = "test-dashboard-password"


def auth_header(
    username=TEST_USERNAME,
    password=TEST_PASSWORD,
):
    credentials = f"{username}:{password}"
    encoded = base64.b64encode(
        credentials.encode("utf-8")
    ).decode("ascii")

    return {
        "Authorization": f"Basic {encoded}"
    }


def configure_auth(monkeypatch):
    monkeypatch.setenv(
        "DASHBOARD_USERNAME",
        TEST_USERNAME,
    )
    monkeypatch.setenv(
        "DASHBOARD_PASSWORD",
        TEST_PASSWORD,
    )


def mock_monitoring_result(window_minutes=5):
    return {
        "monitoring_mode": "on_demand",
        "audit_file_exists": True,
        "valid_events_loaded": 25,
        "invalid_lines": 2,
        "monitoring": {
            "window_minutes": window_minutes,
            "events_in_window": 7,
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


def test_dashboard_requires_authentication(monkeypatch):
    configure_auth(monkeypatch)

    response = client.get("/dashboard/")

    assert response.status_code == 401


def test_dashboard_rejects_invalid_credentials(monkeypatch):
    configure_auth(monkeypatch)

    response = client.get(
        "/dashboard/",
        headers=auth_header(
            password="wrong-password"
        ),
    )

    assert response.status_code == 401


def test_dashboard_rejects_missing_configuration(monkeypatch):
    monkeypatch.delenv(
        "DASHBOARD_USERNAME",
        raising=False,
    )
    monkeypatch.delenv(
        "DASHBOARD_PASSWORD",
        raising=False,
    )

    response = client.get(
        "/dashboard/",
        headers=auth_header(),
    )

    assert response.status_code == 503


def test_dashboard_renders_real_metrics(monkeypatch):
    configure_auth(monkeypatch)

    monkeypatch.setattr(
        dashboard_router,
        "run_live_monitor",
        mock_monitoring_result,
    )

    response = client.get(
        "/dashboard/",
        headers=auth_header(),
    )

    assert response.status_code == 200

    html = response.text

    assert "AI Security Console" in html
    assert "Total Audit Events" in html
    assert "25" in html
    assert "Invalid Log Lines" in html
    assert "Security Detection Findings" in html


def test_dashboard_displays_security_alerts(monkeypatch):
    configure_auth(monkeypatch)

    monkeypatch.setattr(
        dashboard_router,
        "run_live_monitor",
        mock_monitoring_result,
    )

    response = client.get(
        "/dashboard/",
        headers=auth_header(),
    )

    assert response.status_code == 200
    assert "AI-MON-001" in response.text
    assert "Repeated AI evaluation failures" in response.text
    assert "HIGH" in response.text


def test_dashboard_monitoring_failure(monkeypatch):
    configure_auth(monkeypatch)

    def failing_monitor(window_minutes=5):
        raise RuntimeError(
            "Simulated monitoring service failure"
        )

    monkeypatch.setattr(
        dashboard_router,
        "run_live_monitor",
        failing_monitor,
    )

    response = client.get(
        "/dashboard/",
        headers=auth_header(),
    )

    assert response.status_code == 503
    assert (
        response.json()["detail"]
        == "Dashboard monitoring unavailable"
    )


def test_dashboard_does_not_expose_password(monkeypatch):
    configure_auth(monkeypatch)

    monkeypatch.setattr(
        dashboard_router,
        "run_live_monitor",
        mock_monitoring_result,
    )

    response = client.get(
        "/dashboard/",
        headers=auth_header(),
    )

    assert response.status_code == 200
    assert TEST_PASSWORD not in response.text
