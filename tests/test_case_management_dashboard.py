"""Experiment 49: server-rendered dashboard and case API workflow tests.

These tests do not execute JavaScript in a real browser.
"""
from datetime import datetime, timezone
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
import backend.investigation_records as records
import dashboard.router as dashboard_module

AUTH = ('case-analyst', 'local-test-password')
WRITE_HEADERS = {'X-Requested-With': 'XMLHttpRequest', 'Origin': 'http://testserver'}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(records, 'DEFAULT_CASE_FILE', tmp_path / 'cases.jsonl')
    monkeypatch.setenv('DASHBOARD_USERNAME', AUTH[0])
    monkeypatch.setenv('DASHBOARD_PASSWORD', AUTH[1])
    alert = {
        'rule_id': 'AI-MON-004', 'rule_name': 'Knowledge-base integrity failure',
        'severity': 'high', 'request_ids': ['request-001'], 'event_count': 1,
        'threshold': 1, 'window_minutes': 5,
        'detected_at': datetime.now(timezone.utc).isoformat(),
    }
    event = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'event_type': 'ai.security.document_integrity_failure',
        'request_id': 'request-001', 'route': '/chat/rag', 'stage': 'retrieval',
        'decision': 'blocked', 'review_required': True,
    }
    monkeypatch.setattr(
        dashboard_module, 'run_live_monitor',
        lambda window_minutes=5: {
            'valid_events_loaded': 1, 'invalid_lines': 0,
            'monitoring': {'alerts': [alert], 'alert_count': 1, 'events_in_window': 1},
        },
    )
    monkeypatch.setattr(
        dashboard_module, 'load_audit_events',
        lambda: {'events': [event], 'invalid_lines': 0, 'valid_events': 1},
    )
    app = FastAPI()
    app.include_router(dashboard_module.router)
    with TestClient(app) as instance:
        yield instance


def test_monitoring_page_has_case_controls_and_evidence(client):
    response = client.get('/dashboard/monitoring', auth=AUTH)
    assert response.status_code == 200, response.text
    html = response.text
    assert 'id="case-management"' in html
    assert 'id="case-list"' in html
    assert 'data-open-rule="AI-MON-004"' in html
    assert 'Knowledge-base integrity failure' in html
    assert 'request-001' in html
    assert '/chat/rag' in html
    assert 'Investigation Case Management' in html
    assert '/dashboard/cases' in html
    assert '/transition' in html


def test_monitoring_page_requires_authentication(client):
    assert client.get('/dashboard/monitoring').status_code == 401


def test_case_lifecycle_via_dashboard_api(client):
    response = client.post(
        '/dashboard/cases', json={'rule_id': 'AI-MON-004', 'notes': 'Reviewing manifest'},
        headers=WRITE_HEADERS, auth=AUTH,
    )
    assert response.status_code == 201, response.text
    case = response.json()
    assert case['status'] == 'open'
    assert case['request_ids'] == ['request-001']
    case_id = case['case_id']
    assert client.get('/dashboard/cases', auth=AUTH).json()['count'] == 1

    response = client.post(
        f'/dashboard/cases/{case_id}/transition',
        json={'status': 'investigating', 'disposition': 'pending', 'notes': 'Reviewing change history'},
        headers=WRITE_HEADERS, auth=AUTH,
    )
    assert response.status_code == 200, response.text
    assert response.json()['revision'] == 2

    response = client.post(
        f'/dashboard/cases/{case_id}/transition',
        json={'status': 'resolved', 'disposition': 'inconclusive', 'notes': 'Cause undetermined'},
        headers=WRITE_HEADERS, auth=AUTH,
    )
    assert response.status_code == 200, response.text
    assert response.json()['revision'] == 3

    response = client.get(f'/dashboard/cases/{case_id}', auth=AUTH)
    assert response.status_code == 200
    history = response.json()['history']
    assert [row['status'] for row in history] == ['open', 'investigating', 'resolved']
    assert records.DEFAULT_CASE_FILE.exists()
    assert len(records.DEFAULT_CASE_FILE.read_text(encoding='utf-8').splitlines()) == 3


def test_cross_origin_case_write_denied(client):
    response = client.post(
        '/dashboard/cases', json={'rule_id': 'AI-MON-004'},
        headers={'X-Requested-With': 'XMLHttpRequest', 'Origin': 'https://attacker.example'},
        auth=AUTH,
    )
    assert response.status_code == 403
    assert not records.DEFAULT_CASE_FILE.exists()
