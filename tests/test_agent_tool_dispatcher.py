
from uuid import uuid4

import pytest

import backend.agent_tool_dispatcher as dispatcher

from backend.agent_tool_security import (
    AgentSecurityContext,
)


CASE_ID = str(uuid4())
OTHER_CASE_ID = str(uuid4())


@pytest.fixture
def context():
    return AgentSecurityContext(
        principal_id="test-analyst",
        role="analyst",
        authorized_case_ids=frozenset({CASE_ID}),
    )


@pytest.fixture
def trusted_case(monkeypatch):
    case = {
        "case_id": CASE_ID,
        "status": "investigating",
    }

    monkeypatch.setattr(
        dispatcher,
        "load_cases",
        lambda: [case],
    )

    return case


def dispatch(tool, args, context):
    return dispatcher.dispatch_agent_tool_call(
        tool_name=tool,
        arguments=args,
        context=context,
    )


def test_unregistered_tool_is_blocked(context):
    result = dispatch(
        "execute_shell_command",
        {"command": "whoami"},
        context,
    )

    assert result["allowed"] is False
    assert result["executed"] is False


def test_cross_case_access_is_blocked(context):
    result = dispatch(
        "get_incident_timeline",
        {"case_id": OTHER_CASE_ID},
        context,
    )

    assert result["allowed"] is False
    assert result["reason"] == "Case access denied"


def test_missing_case_is_blocked(
    context,
    monkeypatch,
):
    monkeypatch.setattr(
        dispatcher,
        "load_cases",
        lambda: [],
    )

    result = dispatch(
        "get_incident_timeline",
        {"case_id": CASE_ID},
        context,
    )

    assert result["allowed"] is False
    assert result["reason"] == (
        "Investigation case not found"
    )


def test_timeline_is_filtered(
    context,
    trusted_case,
    monkeypatch,
):
    monkeypatch.setattr(
        dispatcher,
        "load_incident_timeline",
        lambda case_id: {
            "events": [
                {
                    "timestamp": (
                        "2026-11-05T12:00:00+00:00"
                    ),
                    "event_type": "case_opened",
                    "status": "open",
                    "notes": "PRIVATE",
                    "secret": "DO_NOT_EXPOSE",
                }
            ]
        },
    )

    result = dispatch(
        "get_incident_timeline",
        {"case_id": CASE_ID},
        context,
    )

    assert result["allowed"] is True

    event = result["data"]["events"][0]

    assert event["status"] == "open"
    assert "notes" not in event
    assert "secret" not in event


def test_other_case_plans_not_returned(
    context,
    trusted_case,
    monkeypatch,
):
    monkeypatch.setattr(
        dispatcher,
        "list_stored_response_plans",
        lambda: [
            {
                "plan_id": str(uuid4()),
                "case_id": CASE_ID,
                "action": "review_audit_logs",
                "status": "proposed",
                "target": "private-target",
            },
            {
                "plan_id": str(uuid4()),
                "case_id": OTHER_CASE_ID,
                "action": "disable_account",
                "status": "pending_approval",
            },
        ],
    )

    result = dispatch(
        "list_response_plans",
        {"case_id": CASE_ID},
        context,
    )

    assert result["allowed"] is True
    assert result["data"]["count"] == 1
    assert "target" not in result["data"]["plans"][0]


def test_response_proposal_is_not_persisted(
    context,
    trusted_case,
):
    result = dispatch(
        "propose_response_action",
        {
            "case_id": CASE_ID,
            "action": "disable_account",
            "target": "test-user",
        },
        context,
    )

    assert result["allowed"] is True

    data = result["data"]

    assert data["requires_approval"] is True
    assert data["persisted"] is False
    assert data["real_action_executed"] is False


def test_resolved_case_cannot_propose(
    context,
    trusted_case,
):
    trusted_case["status"] = "resolved"

    result = dispatch(
        "propose_response_action",
        {
            "case_id": CASE_ID,
            "action": "disable_account",
        },
        context,
    )

    assert result["allowed"] is False


def test_role_forgery_is_blocked(
    context,
    trusted_case,
):
    result = dispatch(
        "propose_response_action",
        {
            "case_id": CASE_ID,
            "action": "disable_account",
            "role": "admin",
        },
        context,
    )

    assert result["allowed"] is False


def test_tool_failure_does_not_leak_paths(
    context,
    monkeypatch,
):
    def failed_retrieval():
        raise RuntimeError(
            "C:/private/secrets/config.json"
        )

    monkeypatch.setattr(
        dispatcher,
        "get_retrieval_service",
        failed_retrieval,
    )

    result = dispatch(
        "search_security_policies",
        {"query": "VPN policy"},
        context,
    )

    assert result["allowed"] is False
    assert "C:/private" not in str(result)


def test_policy_retrieval_is_bounded(
    context,
    monkeypatch,
):
    class FakeRetriever:
        def search(self, query, top_k=3):
            return [
                {
                    "id": "POL-005",
                    "content": "A" * 1000,
                }
            ]

    monkeypatch.setattr(
        dispatcher,
        "get_retrieval_service",
        lambda: FakeRetriever(),
    )

    result = dispatch(
        "search_security_policies",
        {"query": "VPN policy"},
        context,
    )

    assert result["allowed"] is True

    documents = result["data"]["documents"]

    assert len(documents) == 1
    assert len(documents[0]["excerpt"]) == 500


def test_no_real_response_action_occurs(
    context,
    trusted_case,
):
    result = dispatch(
        "propose_response_action",
        {
            "case_id": CASE_ID,
            "action": "revoke_credentials",
        },
        context,
    )

    assert result["allowed"] is True
    assert result["real_action_executed"] is False
    assert result["data"]["execution_mode"] == (
        "simulation_only"
    )
