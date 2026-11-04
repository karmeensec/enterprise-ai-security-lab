
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import backend.log_monitor_service as monitor_module
from backend.main import app


def integrity_event(request_id, timestamp):
    return {
        "timestamp": timestamp.isoformat(),
        "event_type": "ai.security.document_integrity_failure",
        "request_id": request_id,
        "route": "/chat/rag",
        "stage": "retrieval",
        "decision": "blocked",
        "review_required": True,
    }


@pytest.fixture
def monitor_client(tmp_path, monkeypatch):
    audit_file = tmp_path / "security_audit.jsonl"

    monkeypatch.setattr(
        monitor_module,
        "AUDIT_FILE",
        audit_file,
    )

    monkeypatch.setenv(
        "MONITOR_API_KEY",
        "experiment48-test-key",
    )

    now = datetime.now(timezone.utc)

    events = [
        integrity_event(
            str(uuid.uuid4()),
            now - timedelta(seconds=10),
        ),
        integrity_event(
            str(uuid.uuid4()),
            now - timedelta(seconds=20),
        ),
        integrity_event(
            str(uuid.uuid4()),
            now - timedelta(seconds=30),
        ),
    ]

    audit_file.write_text(
        "\n".join(json.dumps(e) for e in events) + "\n",
        encoding="utf-8",
    )

    with TestClient(app) as client:
        yield client, audit_file


def test_api_detects_integrity_alerts(monitor_client):
    client, _ = monitor_client

    response = client.get(
        "/security/monitor?window_minutes=5",
        headers={
            "X-Monitor-API-Key": "experiment48-test-key"
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["valid_events_loaded"] == 3
    assert data["invalid_lines"] == 0

    alerts = {
        alert["rule_id"]: alert
        for alert in data["monitoring"]["alerts"]
    }

    assert "AI-MON-004" in alerts
    assert "AI-MON-005" in alerts

    assert alerts["AI-MON-004"]["severity"] == "high"
    assert alerts["AI-MON-005"]["severity"] == "critical"
    assert alerts["AI-MON-005"]["event_count"] == 3

    assert "AI-MON-001" not in alerts
    assert "AI-MON-002" not in alerts
    assert "AI-MON-003" not in alerts


def test_api_requires_monitor_credentials(monitor_client):
    client, _ = monitor_client

    response = client.get(
        "/security/monitor?window_minutes=5"
    )

    assert response.status_code == 401


def test_duplicate_event_does_not_increase_count(
    monitor_client,
):
    client, audit_file = monitor_client

    event = integrity_event(
        str(uuid.uuid4()),
        datetime.now(timezone.utc),
    )

    audit_file.write_text(
        "\n".join(
            json.dumps(event) for _ in range(3)
        ) + "\n",
        encoding="utf-8",
    )

    response = client.get(
        "/security/monitor?window_minutes=5",
        headers={
            "X-Monitor-API-Key": "experiment48-test-key"
        },
    )

    assert response.status_code == 200

    alerts = {
        alert["rule_id"]: alert
        for alert in response.json()["monitoring"]["alerts"]
    }

    assert alerts["AI-MON-004"]["event_count"] == 1
    assert "AI-MON-005" not in alerts
