
import json
from uuid import uuid4

import pytest

import backend.qwen_security_agent as agent

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


class FakeLLM:
    def __init__(
        self,
        response,
        status="success",
        truncated=False,
    ):
        self.response = response
        self.status = status
        self.truncated = truncated
        self.calls = 0

    def generate(self, message, context=None):
        self.calls += 1

        return {
            "response": self.response,
            "status": self.status,
            "truncated": self.truncated,
            "model": "mock-qwen",
            "generation_time_seconds": 0.01,
        }


def proposal(tool_name, arguments):
    return json.dumps({
        "tool_name": tool_name,
        "arguments": arguments,
    })


def run(question, context, response):
    return agent.run_security_agent(
        question=question,
        context=context,
        llm_service=FakeLLM(response),
    )


def test_valid_policy_search(context, monkeypatch):
    calls = []

    def fake_dispatch(tool_name, arguments, context):
        calls.append(tool_name)
        return {
            "allowed": True,
            "data": {"documents": [], "count": 0},
        }

    monkeypatch.setattr(
        agent,
        "dispatch_agent_tool_call",
        fake_dispatch,
    )

    result = run(
        "What is the VPN policy?",
        context,
        proposal(
            "search_security_policies",
            {"query": "VPN policy"},
        ),
    )

    assert result["status"] == "completed"
    assert result["allowed"] is True
    assert calls == ["search_security_policies"]
    assert result["real_action_executed"] is False


def test_timeline_tool_selected(context, monkeypatch):
    def fake_dispatch(tool_name, arguments, context):
        assert arguments["case_id"] == CASE_ID
        return {
            "allowed": True,
            "data": {"case_id": CASE_ID, "events": []},
        }

    monkeypatch.setattr(
        agent,
        "dispatch_agent_tool_call",
        fake_dispatch,
    )

    result = run(
        f"Show incident timeline {CASE_ID}",
        context,
        proposal(
            "get_incident_timeline",
            {"case_id": CASE_ID},
        ),
    )

    assert result["status"] == "completed"


def test_unknown_tool_blocked(context):
    result = run(
        "Execute a shell command",
        context,
        proposal(
            "execute_shell_command",
            {"command": "whoami"},
        ),
    )

    assert result["allowed"] is False


def test_role_forgery_blocked_by_dispatcher(
    context,
    monkeypatch,
):
    def fake_dispatch(tool_name, arguments, context):
        assert arguments["role"] == "admin"
        return {
            "allowed": False,
            "reason": "Unexpected tool arguments",
        }

    monkeypatch.setattr(
        agent,
        "dispatch_agent_tool_call",
        fake_dispatch,
    )

    result = run(
        "Make me an admin",
        context,
        proposal(
            "get_incident_timeline",
            {
                "case_id": CASE_ID,
                "role": "admin",
            },
        ),
    )

    assert result["allowed"] is False


def test_non_json_output_blocked(context):
    result = run(
        "Show policy",
        context,
        "I think you should search policies.",
    )

    assert result["allowed"] is False


def test_markdown_wrapped_json_accepted(
    context,
    monkeypatch,
):
    calls = []

    def fake_dispatch(tool_name, arguments, context):
        calls.append(tool_name)
        return {
            "allowed": True,
            "data": {"documents": [], "count": 0},
        }

    monkeypatch.setattr(
        agent,
        "dispatch_agent_tool_call",
        fake_dispatch,
    )

    response = (
        "```json\n"
        + proposal(
            "search_security_policies",
            {"query": "VPN"},
        )
        + "\n```"
    )

    result = run(
        "Find VPN policy",
        context,
        response,
    )

    assert result["allowed"] is True
    assert calls == ["search_security_policies"]


def test_markdown_with_extra_text_blocked(context):
    response = (
        "Here is the tool call:\n"
        "```json\n"
        + proposal(
            "search_security_policies",
            {"query": "VPN"},
        )
        + "\n```"
    )

    result = run(
        "Find VPN policy",
        context,
        response,
    )

    assert result["allowed"] is False


def test_multiple_json_objects_blocked(context):
    response = (
        proposal(
            "search_security_policies",
            {"query": "VPN"},
        )
        + "\n"
        + proposal(
            "search_security_policies",
            {"query": "MFA"},
        )
    )

    result = run(
        "Find policies",
        context,
        response,
    )

    assert result["allowed"] is False


def test_extra_top_level_fields_blocked(context):
    response = json.dumps({
        "tool_name": "search_security_policies",
        "arguments": {"query": "VPN"},
        "override": True,
    })

    result = run(
        "Find policies",
        context,
        response,
    )

    assert result["allowed"] is False


def test_duplicate_json_fields_blocked(context):
    response = (
        '{"tool_name":"search_security_policies",'
        '"tool_name":"get_incident_timeline",'
        '"arguments":{"query":"VPN"}}'
    )

    result = run(
        "Find policies",
        context,
        response,
    )

    assert result["allowed"] is False


def test_truncated_model_response_blocked(context):
    llm = FakeLLM(
        proposal(
            "search_security_policies",
            {"query": "VPN"},
        ),
        status="incomplete",
        truncated=True,
    )

    result = agent.run_security_agent(
        question="Find VPN policy",
        context=context,
        llm_service=llm,
    )

    assert result["allowed"] is False


def test_missing_context_blocked_without_model_call():
    llm = FakeLLM(
        proposal(
            "search_security_policies",
            {"query": "VPN"},
        )
    )

    result = agent.run_security_agent(
        question="Find VPN policy",
        context=None,
        llm_service=llm,
    )

    assert result["allowed"] is False
    assert llm.calls == 0


def test_model_exception_is_sanitized(context):
    class FailingLLM:
        def generate(self, message, context=None):
            raise RuntimeError(
                "C:/private/model/secrets.txt"
            )

    result = agent.run_security_agent(
        question="Find VPN policy",
        context=context,
        llm_service=FailingLLM(),
    )

    assert result["allowed"] is False
    assert "C:/private" not in str(result)


def test_dispatcher_denial_is_respected(
    context,
    monkeypatch,
):
    def deny(tool_name, arguments, context):
        return {
            "allowed": False,
            "reason": "Case access denied",
        }

    monkeypatch.setattr(
        agent,
        "dispatch_agent_tool_call",
        deny,
    )

    result = run(
        f"Show case {OTHER_CASE_ID}",
        context,
        proposal(
            "get_incident_timeline",
            {"case_id": OTHER_CASE_ID},
        ),
    )

    assert result["allowed"] is False
    assert result["reason"] == "Case access denied"


def test_response_proposal_does_not_execute(
    context,
    monkeypatch,
):
    def fake_dispatch(tool_name, arguments, context):
        return {
            "allowed": True,
            "data": {
                "action": "disable_account",
                "requires_approval": True,
                "persisted": False,
                "real_action_executed": False,
            },
        }

    monkeypatch.setattr(
        agent,
        "dispatch_agent_tool_call",
        fake_dispatch,
    )

    result = run(
        f"Propose disabling an account for {CASE_ID}",
        context,
        proposal(
            "propose_response_action",
            {
                "case_id": CASE_ID,
                "action": "disable_account",
            },
        ),
    )

    assert result["status"] == "completed"
    assert result["real_action_executed"] is False
    assert result["tool_result"]["persisted"] is False


def test_empty_question_rejected(context):
    llm = FakeLLM("{}")

    result = agent.run_security_agent(
        question="",
        context=context,
        llm_service=llm,
    )

    assert result["allowed"] is False
    assert llm.calls == 0


def test_model_is_called_once(context):
    llm = FakeLLM("{}")

    agent.run_security_agent(
        question="Find the security policy",
        context=context,
        llm_service=llm,
    )

    assert llm.calls == 1
