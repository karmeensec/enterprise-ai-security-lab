
import base64

import pytest
from fastapi.testclient import TestClient

import dashboard.router as dashboard_router
from backend.main import app


client = TestClient(app)

USERNAME = "investigation-test-admin"
PASSWORD = "investigation-test-password"


def auth_headers():
    raw = f"{USERNAME}:{PASSWORD}"

    encoded = base64.b64encode(
        raw.encode("utf-8")
    ).decode("ascii")

    return {
        "Authorization": f"Basic {encoded}"
    }


@pytest.fixture
def investigation_setup(monkeypatch):
    monkeypatch.setenv(
        "DASHBOARD_USERNAME",
        USERNAME,
    )
    monkeypatch.setenv(
        "DASHBOARD_PASSWORD",
        PASSWORD,
    )

    events = [
        {
            "timestamp": "2026-10-29T12:00:00+00:00",
            "event_type": "ai.security.evaluation",
            "request_id": "investigation-001",
            "cited_document": "POL-005",
            "decision": "evaluation_error",
            "review_required": True,
            "duration_ms": 125.0,
        },
        {
            "timestamp": "2026-10-29T12:01:00+00:00",
            "event_type": "ai.security.evaluation",
            "request_id": "investigation-002",
            "cited_document": "POL-005",
            "decision": "evaluation_error",
            "review_required": True,
            "duration_ms": 130.0,
        },
        {
            "timestamp": "2026-10-29T12:02:00+00:00",
            "event_type": "ai.security.evaluation",
            "request_id": "investigation-003",
            "cited_document": "POL-005",
            "decision": "evaluation_error",
            "review_required": True,
            "duration_ms": 120.0,
        },
    ]

    def fake_monitor(window_minutes=5):
        return {
            "monitoring_mode": "on_demand",
            "audit_file_exists": True,
            "valid_events_loaded": len(events),
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
                        "threshold": 3,
                        "event_count": 3,
                        "request_ids": [
                            "investigation-001",
                            "investigation-002",
                            "investigation-003",
                        ],
                    }
                ],
            },
        }

    def fake_audit_reader():
        return {
            "events": events,
            "valid_events": len(events),
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
        fake_audit_reader,
    )


def test_investigation_details_render(investigation_setup):
    response = client.get(
        "/dashboard/monitoring?window_minutes=60",
        headers=auth_headers(),
    )

    assert response.status_code == 200
    assert "View Investigation Evidence" in response.text
    assert "3 records" in response.text


def test_all_evidence_request_ids_displayed(
    investigation_setup,
):
    response = client.get(
        "/dashboard/monitoring",
        headers=auth_headers(),
    )

    for request_id in (
        "investigation-001",
        "investigation-002",
        "investigation-003",
    ):
        assert request_id in response.text


def test_evidence_decisions_displayed(investigation_setup):
    response = client.get(
        "/dashboard/monitoring",
        headers=auth_headers(),
    )

    assert response.status_code == 200
    assert "evaluation_error" in response.text
    assert "POL-005" in response.text


def test_audit_event_links_render(investigation_setup):
    response = client.get(
        "/dashboard/monitoring",
        headers=auth_headers(),
    )

    assert response.status_code == 200
    assert (
        "/dashboard/events?request_id=investigation-001"
        in response.text
    )


def test_audit_event_navigation(investigation_setup):
    response = client.get(
        "/dashboard/events?request_id=investigation-002",
        headers=auth_headers(),
    )

    assert response.status_code == 200
    assert "investigation-002" in response.text
    assert "investigation-001" not in response.text
    assert "investigation-003" not in response.text


def test_investigation_requires_authentication(
    investigation_setup,
):
    response = client.get(
        "/dashboard/monitoring",
    )

    assert response.status_code == 401


def test_no_claim_content_exposed(
    investigation_setup,
    monkeypatch,
):
    sensitive = "PRIVATE_CLAIM_VALUE_12345"

    def fake_reader():
        return {
            "events": [
                {
                    "timestamp": "2026-10-29T12:00:00+00:00",
                    "event_type": "ai.security.evaluation",
                    "request_id": "investigation-001",
                    "cited_document": "POL-005",
                    "decision": "evaluation_error",
                    "claim": sensitive,
                }
            ],
            "valid_events": 1,
            "invalid_lines": 0,
            "file_exists": True,
        }

    monkeypatch.setattr(
        dashboard_router,
        "load_audit_events",
        fake_reader,
    )

    response = client.get(
        "/dashboard/monitoring",
        headers=auth_headers(),
    )

    assert response.status_code == 200
    assert sensitive not in response.text
