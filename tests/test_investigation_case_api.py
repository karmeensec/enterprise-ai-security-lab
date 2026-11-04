"""Experiment 49: authenticated analyst case workflow tests."""

from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import backend.investigation_records as records
import dashboard.router as dashboard_module


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(records, "DEFAULT_CASE_FILE", tmp_path / "cases.jsonl")
    monkeypatch.setenv("DASHBOARD_USERNAME", "investigator")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "local-test-password")
    timestamp = datetime.now(timezone.utc).isoformat()
    alert = {
        "rule_id": "AI-MON-004",
        "rule_name": "Knowledge-base integrity failure",
        "severity": "high",
        "request_ids": ["request-001"],
        "event_count": 1,
        "threshold": 1,
    }
    event = {
        "timestamp": timestamp,
        "event_type": "ai.security.document_integrity_failure",
        "request_id": "request-001",
        "route": "/chat/rag",
        "stage": "retrieval",
        "decision": "blocked",
        "review_required": True,
    }
    monkeypatch.setattr(
        dashboard_module,
        "run_live_monitor",
        lambda window_minutes=5: {"monitoring": {"alerts": [alert]}},
    )
    monkeypatch.setattr(
        dashboard_module,
        "load_audit_events",
        lambda: {"events": [event], "invalid_lines": 0},
    )
    app = FastAPI()
    app.include_router(dashboard_module.router)
    with TestClient(app) as instance:
        yield instance


def headers():
    return {
        "X-Requested-With": "XMLHttpRequest",
        "Origin": "http://testserver",
    }


def credentials():
    return ("investigator", "local-test-password")


def test_read_cases_requires_auth(client):
    assert client.get("/dashboard/cases").status_code == 401


def test_create_case_requires_auth(client):
    response = client.post(
        "/dashboard/cases", json={"rule_id": "AI-MON-004"}, headers=headers()
    )
    assert response.status_code == 401


def test_create_case_requires_csrf_headers(client):
    response = client.post(
        "/dashboard/cases", json={"rule_id": "AI-MON-004"}, auth=credentials()
    )
    assert response.status_code == 403


def test_cross_origin_write_blocked(client):
    response = client.post(
        "/dashboard/cases",
        json={"rule_id": "AI-MON-004"},
        headers={**headers(), "Origin": "https://attacker.example"},
        auth=credentials(),
    )
    assert response.status_code == 403


def test_create_and_transition_case(client):
    result = client.post(
        "/dashboard/cases",
        json={"rule_id": "AI-MON-004", "notes": "Investigate policy integrity"},
        headers=headers(), auth=credentials(),
    )
    assert result.status_code == 201, result.text
    record = result.json()
    assert record["status"] == "open"
    assert record["request_ids"] == ["request-001"]
    assert record["analyst"] == "investigator"
    case_id = record["case_id"]

    working = client.post(
        f"/dashboard/cases/{case_id}/transition",
        json={"status": "investigating", "notes": "Reviewing change history"},
        headers=headers(), auth=credentials(),
    )
    assert working.status_code == 200, working.text
    assert working.json()["revision"] == 2

    resolved = client.post(
        f"/dashboard/cases/{case_id}/transition",
        json={"status": "resolved", "disposition": "inconclusive", "notes": "Cause undetermined"},
        headers=headers(), auth=credentials(),
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["revision"] == 3

    history = client.get(f"/dashboard/cases/{case_id}", auth=credentials())
    assert history.status_code == 200
    assert len(history.json()["history"]) == 3
    assert len(client.get("/dashboard/cases", auth=credentials()).json()["cases"]) == 1


def test_caller_cannot_forge_evidence(client):
    response = client.post(
        "/dashboard/cases",
        json={"rule_id": "AI-MON-004", "request_ids": ["forged"]},
        headers=headers(), auth=credentials(),
    )
    assert response.status_code == 422


def test_no_current_alert_cannot_create_case(client):
    response = client.post(
        "/dashboard/cases", json={"rule_id": "AI-MON-999"},
        headers=headers(), auth=credentials(),
    )
    assert response.status_code == 404


def test_invalid_status_transition_rejected(client):
    result = client.post(
        "/dashboard/cases", json={"rule_id": "AI-MON-004"},
        headers=headers(), auth=credentials(),
    )
    case_id = result.json()["case_id"]
    response = client.post(
        f"/dashboard/cases/{case_id}/transition",
        json={"status": "resolved", "disposition": "benign"},
        headers=headers(), auth=credentials(),
    )
    assert response.status_code == 422
