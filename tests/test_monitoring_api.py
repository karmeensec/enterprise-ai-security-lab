
from fastapi.testclient import TestClient

import backend.main as main


client = TestClient(main.app)

TEST_API_KEY = "local-test-monitoring-key"


def mock_monitoring_result():
    return {
        "monitoring_mode": "on_demand",
        "audit_file_exists": True,
        "valid_events_loaded": 3,
        "invalid_lines": 0,
        "monitoring": {
            "window_minutes": 5,
            "events_in_window": 3,
            "alert_count": 1,
            "alerts": [
                {
                    "rule_id": "AI-MON-001",
                    "severity": "high",
                    "event_count": 3,
                }
            ],
        },
    }


def test_missing_api_key_rejected(monkeypatch):
    monkeypatch.setenv("MONITOR_API_KEY", TEST_API_KEY)

    response = client.get("/security/monitor")

    assert response.status_code == 401


def test_invalid_api_key_rejected(monkeypatch):
    monkeypatch.setenv("MONITOR_API_KEY", TEST_API_KEY)

    response = client.get(
        "/security/monitor",
        headers={"x-monitor-api-key": "wrong-key"},
    )

    assert response.status_code == 401


def test_valid_api_key_accepted(monkeypatch):
    monkeypatch.setenv("MONITOR_API_KEY", TEST_API_KEY)

    monkeypatch.setattr(
        main,
        "run_live_monitor",
        lambda window_minutes=5: mock_monitoring_result(),
    )

    response = client.get(
        "/security/monitor",
        headers={"x-monitor-api-key": TEST_API_KEY},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["monitoring"]["alert_count"] == 1
    assert data["monitoring"]["alerts"][0]["rule_id"] == "AI-MON-001"


def test_invalid_window_rejected(monkeypatch):
    monkeypatch.setenv("MONITOR_API_KEY", TEST_API_KEY)

    response = client.get(
        "/security/monitor?window_minutes=100",
        headers={"x-monitor-api-key": TEST_API_KEY},
    )

    assert response.status_code == 422


def test_missing_server_configuration(monkeypatch):
    monkeypatch.delenv("MONITOR_API_KEY", raising=False)

    response = client.get(
        "/security/monitor",
        headers={"x-monitor-api-key": TEST_API_KEY},
    )

    assert response.status_code == 503


def test_monitoring_failure_returns_503(monkeypatch):
    monkeypatch.setenv("MONITOR_API_KEY", TEST_API_KEY)

    def failing_monitor(window_minutes=5):
        raise RuntimeError("Simulated monitoring failure")

    monkeypatch.setattr(
        main,
        "run_live_monitor",
        failing_monitor,
    )

    response = client.get(
        "/security/monitor",
        headers={"x-monitor-api-key": TEST_API_KEY},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "Security monitoring temporarily unavailable"
    )
