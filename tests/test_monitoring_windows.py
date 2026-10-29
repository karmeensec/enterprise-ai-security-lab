
import base64

import pytest
from fastapi.testclient import TestClient

import dashboard.router as dashboard_router
from backend.main import app


client = TestClient(app)

USERNAME = "test-monitor-admin"
PASSWORD = "test-monitor-password"


def auth_headers():
    credentials = f"{USERNAME}:{PASSWORD}"
    encoded = base64.b64encode(
        credentials.encode("utf-8")
    ).decode("ascii")

    return {
        "Authorization": f"Basic {encoded}"
    }


@pytest.fixture
def monitoring_setup(monkeypatch):
    monkeypatch.setenv("DASHBOARD_USERNAME", USERNAME)
    monkeypatch.setenv("DASHBOARD_PASSWORD", PASSWORD)

    called_windows = []

    def fake_monitor(window_minutes=5):
        called_windows.append(window_minutes)

        return {
            "monitoring_mode": "on_demand",
            "audit_file_exists": True,
            "valid_events_loaded": 20,
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

    monkeypatch.setattr(
        dashboard_router,
        "run_live_monitor",
        fake_monitor,
    )

    return called_windows


@pytest.mark.parametrize(
    "minutes",
    [5, 15, 30, 60],
)
def test_valid_monitoring_windows(monitoring_setup, minutes):
    response = client.get(
        f"/dashboard/monitoring?window_minutes={minutes}",
        headers=auth_headers(),
    )

    assert response.status_code == 200
    assert monitoring_setup == [minutes]
    assert f"last {minutes} minutes" in response.text
    assert f"{minutes} minutes" in response.text


def test_default_monitoring_window(monitoring_setup):
    response = client.get(
        "/dashboard/monitoring",
        headers=auth_headers(),
    )

    assert response.status_code == 200
    assert monitoring_setup == [5]


@pytest.mark.parametrize(
    "value",
    ["0", "-5", "61", "100", "invalid"],
)
def test_invalid_monitoring_windows_rejected(
    monitoring_setup,
    value,
):
    response = client.get(
        f"/dashboard/monitoring?window_minutes={value}",
        headers=auth_headers(),
    )

    assert response.status_code == 422
    assert monitoring_setup == []


def test_monitoring_requires_authentication(monitoring_setup):
    response = client.get(
        "/dashboard/monitoring?window_minutes=30"
    )

    assert response.status_code == 401
    assert monitoring_setup == []


def test_monitoring_alert_details(monitoring_setup):
    response = client.get(
        "/dashboard/monitoring?window_minutes=30",
        headers=auth_headers(),
    )

    assert response.status_code == 200
    assert "AI-MON-001" in response.text
    assert "Repeated AI evaluation failures" in response.text
    assert "HIGH" in response.text
    assert "3 matching events" in response.text


def test_selected_option_is_preserved(monitoring_setup):
    response = client.get(
        "/dashboard/monitoring?window_minutes=30",
        headers=auth_headers(),
    )

    assert response.status_code == 200

    html = response.text

    assert 'value="30"' in html
    assert "selected" in html
