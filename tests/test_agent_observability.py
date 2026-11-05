
import json
from datetime import datetime, timedelta, timezone

import pytest

import backend.agent_observability as obs

from backend.agent_tool_security import AgentSecurityContext


@pytest.fixture
def context():
    return AgentSecurityContext(
        principal_id="test-analyst",
        role="analyst",
        authorized_case_ids=frozenset(),
    )


def blocked_result(
    reason="Case access denied",
    tool="get_incident_timeline",
):
    return {
        "status": "blocked",
        "allowed": False,
        "reason": reason,
        "tool_name": tool,
        "tool_result": None,
        "real_action_executed": False,
    }


def test_records_sanitized_agent_event(
    tmp_path,
    context,
):
    path = tmp_path / "security_audit.jsonl"

    result = {
        **blocked_result(),
        "prompt": "PRIVATE PROMPT",
        "secret": "PRIVATE SECRET",
        "tool_result": {
            "password": "PRIVATE PASSWORD"
        },
    }

    event = obs.record_agent_activity(
        result,
        context,
        file_path=path,
    )

    content = path.read_text(
        encoding="utf-8"
    )

    assert event["decision"] == "blocked"
    assert event["reason_category"] == (
        "case_access_denied"
    )

    assert "PRIVATE" not in content
    assert "test-analyst" not in content
    assert "password" not in content


def test_monitored_agent_records_denial(
    monkeypatch,
    tmp_path,
    context,
):
    monkeypatch.setattr(
        obs,
        "run_security_agent",
        lambda **kwargs: blocked_result(),
    )

    path = tmp_path / "audit.jsonl"

    result = obs.run_monitored_security_agent(
        question="Show unauthorized case",
        context=context,
        audit_file=path,
    )

    assert result["allowed"] is False

    loaded = obs.load_agent_events(path)

    assert len(loaded["events"]) == 1


def test_existing_audit_event_is_preserved(
    tmp_path,
    context,
):
    path = tmp_path / "audit.jsonl"

    legacy = {
        "event_type": "ai.security.evaluation",
        "request_id": "legacy-request",
        "decision": "review_required",
        "cited_document": "POL-001",
    }

    path.write_text(
        json.dumps(legacy) + "\n",
        encoding="utf-8",
    )

    obs.record_agent_activity(
        blocked_result(),
        context,
        file_path=path,
    )

    lines = path.read_text(
        encoding="utf-8"
    ).splitlines()

    assert len(lines) == 2
    assert json.loads(lines[0]) == legacy

    loaded = obs.load_agent_events(path)

    assert len(loaded["events"]) == 1


def test_three_denials_trigger_detection(
    tmp_path,
    context,
):
    path = tmp_path / "audit.jsonl"

    for _ in range(3):
        obs.record_agent_activity(
            blocked_result(),
            context,
            file_path=path,
        )

    result = obs.run_agent_monitor(
        file_path=path
    )

    rule_ids = {
        alert["rule_id"]
        for alert in result["monitoring"]["alerts"]
    }

    assert "AI-MON-006" in rule_ids
    assert "AI-MON-007" in rule_ids


def test_unknown_tool_detection(
    tmp_path,
    context,
):
    path = tmp_path / "audit.jsonl"

    obs.record_agent_activity(
        blocked_result(
            reason="Tool is not in the agent allowlist",
            tool=None,
        ),
        context,
        file_path=path,
    )

    result = obs.run_agent_monitor(
        file_path=path
    )

    rule_ids = {
        alert["rule_id"]
        for alert in result["monitoring"]["alerts"]
    }

    assert "AI-MON-008" in rule_ids


def test_separate_principals_not_combined(
    tmp_path,
):
    path = tmp_path / "audit.jsonl"

    for index in range(3):
        context = AgentSecurityContext(
            principal_id=f"analyst-{index}",
            role="analyst",
            authorized_case_ids=frozenset(),
        )

        obs.record_agent_activity(
            blocked_result(
                reason="Invalid case identifier"
            ),
            context,
            file_path=path,
        )

    result = obs.run_agent_monitor(
        file_path=path
    )

    rule_ids = {
        alert["rule_id"]
        for alert in result["monitoring"]["alerts"]
    }

    assert "AI-MON-006" not in rule_ids


def test_old_events_outside_detection_window(
    tmp_path,
    context,
):
    path = tmp_path / "audit.jsonl"

    event = obs.record_agent_activity(
        blocked_result(
            reason="Invalid case identifier"
        ),
        context,
        file_path=path,
    )

    event["timestamp"] = (
        datetime.now(timezone.utc)
        - timedelta(minutes=30)
    ).isoformat()

    path.write_text(
        json.dumps(event) + "\n",
        encoding="utf-8",
    )

    result = obs.run_agent_monitor(
        file_path=path
    )

    assert (
        result["monitoring"]["alert_count"]
        == 0
    )


def test_invalid_agent_record_excluded(
    tmp_path,
):
    path = tmp_path / "audit.jsonl"

    path.write_text(
        '{"event_type":"ai.security.agent_tool_activity",'
        '"request_id":"invalid"}\n',
        encoding="utf-8",
    )

    loaded = obs.load_agent_events(path)

    assert loaded["events"] == []
    assert loaded["invalid_lines"] == 1


def test_real_action_claim_rejected(
    tmp_path,
    context,
):
    result = blocked_result()
    result["real_action_executed"] = True

    with pytest.raises(
        ValueError,
        match="real-action",
    ):
        obs.record_agent_activity(
            result,
            context,
            file_path=tmp_path / "audit.jsonl",
        )


def test_authorized_request_recorded(
    tmp_path,
    context,
):
    path = tmp_path / "audit.jsonl"

    result = {
        "status": "completed",
        "allowed": True,
        "reason": None,
        "tool_name": "search_security_policies",
        "real_action_executed": False,
    }

    event = obs.record_agent_activity(
        result,
        context,
        file_path=path,
    )

    assert event["decision"] == "allowed"
    assert event["reason_category"] == "none"


def test_monitor_with_missing_file(tmp_path):
    result = obs.run_agent_monitor(
        file_path=tmp_path / "missing.jsonl"
    )

    assert result["agent_events_loaded"] == 0
    assert result["monitoring"]["alert_count"] == 0
