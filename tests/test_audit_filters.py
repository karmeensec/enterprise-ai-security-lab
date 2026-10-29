
import base64

import pytest
from fastapi.testclient import TestClient

import dashboard.router as dashboard_router
from backend.main import app


client = TestClient(app)

USERNAME = "filter-test-admin"
PASSWORD = "filter-test-password"


def auth_headers():
    raw = f"{USERNAME}:{PASSWORD}"
    encoded = base64.b64encode(
        raw.encode("utf-8")
    ).decode("ascii")

    return {"Authorization": f"Basic {encoded}"}


@pytest.fixture
def setup_filters(monkeypatch):
    monkeypatch.setenv(
        "DASHBOARD_USERNAME", USERNAME
    )
    monkeypatch.setenv(
        "DASHBOARD_PASSWORD", PASSWORD
    )

    events = [
        {
            "timestamp": "2026-10-28T12:00:00+00:00",
            "request_id": "request-alpha",
            "event_type": "ai.security.evaluation",
            "cited_document": "POL-005",
            "decision": "supported_by_checks",
        },
        {
            "timestamp": "2026-10-28T12:01:00+00:00",
            "request_id": "request-beta",
            "event_type": "ai.security.evaluation",
            "cited_document": "POL-001",
            "decision": "evaluation_error",
        },
        {
            "timestamp": "2026-10-28T12:02:00+00:00",
            "request_id": "request-gamma",
            "event_type": "ai.security.evaluation",
            "cited_document": "POL-003",
            "decision": "review_required",
        },
    ]

    def fake_load():
        return {
            "events": events,
            "valid_events": len(events),
            "invalid_lines": 0,
            "file_exists": True,
        }

    monkeypatch.setattr(
        dashboard_router,
        "load_audit_events",
        fake_load,
    )


def get_events(query=""):
    return client.get(
        "/dashboard/events" + query,
        headers=auth_headers(),
    )


def test_default_events_displayed(setup_filters):
    response = get_events()

    assert response.status_code == 200
    assert "request-alpha" in response.text
    assert "request-beta" in response.text
    assert "request-gamma" in response.text


def test_filter_by_decision(setup_filters):
    response = get_events(
        "?decision=evaluation_error"
    )

    assert response.status_code == 200
    assert "request-beta" in response.text
    assert "request-alpha" not in response.text
    assert "request-gamma" not in response.text


def test_search_by_request_id(setup_filters):
    response = get_events(
        "?request_id=alpha"
    )

    assert response.status_code == 200
    assert "request-alpha" in response.text
    assert "request-beta" not in response.text


def test_combined_filters(setup_filters):
    response = get_events(
        "?decision=evaluation_error&request_id=beta"
    )

    assert response.status_code == 200
    assert "request-beta" in response.text
    assert "request-alpha" not in response.text


def test_result_limit(setup_filters):
    response = get_events("?limit=1")

    assert response.status_code == 200
    assert "request-gamma" in response.text
    assert "request-beta" not in response.text
    assert "request-alpha" not in response.text


@pytest.mark.parametrize(
    "query",
    [
        "?limit=0",
        "?limit=101",
        "?limit=invalid",
        "?decision=invalid_decision",
        "?request_id=" + ("x" * 129),
    ],
)
def test_invalid_parameters_rejected(setup_filters, query):
    response = get_events(query)

    assert response.status_code == 422


def test_request_id_case_insensitive(setup_filters):
    response = get_events("?request_id=ALPHA")

    assert response.status_code == 200
    assert "request-alpha" in response.text


def test_html_injection_escaped(
    setup_filters,
    monkeypatch,
):
    malicious = "<script>alert('xss')</script>"

    def fake_load():
        return {
            "events": [
                {
                    "timestamp": "2026-10-28T12:00:00+00:00",
                    "request_id": malicious,
                    "event_type": "ai.security.evaluation",
                    "cited_document": "POL-005",
                    "decision": "review_required",
                }
            ],
            "valid_events": 1,
            "invalid_lines": 0,
            "file_exists": True,
        }

    monkeypatch.setattr(
        dashboard_router,
        "load_audit_events",
        fake_load,
    )

    response = get_events()

    assert response.status_code == 200
    assert malicious not in response.text
    assert "&lt;script&gt;" in response.text


def test_unauthenticated_filter_rejected(setup_filters):
    response = client.get(
        "/dashboard/events?decision=evaluation_error"
    )

    assert response.status_code == 401
