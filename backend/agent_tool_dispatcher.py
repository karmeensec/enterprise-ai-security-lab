
"""
Experiment 52 — Controlled AI Agent Tool Dispatcher.

Only explicitly registered tools can run.

The authorization context must be constructed by a
trusted server component, never by the LLM.

Response actions are proposals only.
No real incident-response actions are performed.
"""

from typing import Any

from backend.agent_tool_security import (
    AgentSecurityContext,
    authorize_agent_tool_call,
)
from backend.investigation_records import load_cases
from backend.response_plan_store import (
    list_stored_response_plans,
)
from backend.response_policy_engine import (
    create_response_plan,
)
from backend.incident_timeline_service import (
    load_incident_timeline,
)
from backend.retrieval_service import (
    get_retrieval_service,
)


MAX_OUTPUT_EVENTS = 100
MAX_OUTPUT_DOCUMENTS = 3
MAX_EXCERPT_LENGTH = 500


def _blocked(reason: str) -> dict[str, Any]:
    return {
        "allowed": False,
        "decision": "blocked",
        "reason": reason,
        "executed": False,
        "real_action_executed": False,
        "data": None,
    }


def _find_case(case_id: str) -> dict | None:
    cases = load_cases()

    for case in cases:
        if case.get("case_id") == case_id:
            return case

    return None


def _search_policies(arguments: dict) -> dict:
    retriever = get_retrieval_service()

    documents = retriever.search(
        arguments["query"],
        top_k=MAX_OUTPUT_DOCUMENTS,
    )

    safe_documents = []

    for document in documents[:MAX_OUTPUT_DOCUMENTS]:
        if not isinstance(document, dict):
            continue

        document_id = document.get(
            "document_id",
            document.get("id"),
        )

        content = document.get(
            "content",
            document.get("text", ""),
        )

        if not isinstance(document_id, str):
            continue

        if not isinstance(content, str):
            content = ""

        safe_documents.append({
            "document_id": document_id,
            "excerpt": content[:MAX_EXCERPT_LENGTH],
        })

    return {
        "documents": safe_documents,
        "count": len(safe_documents),
        "source": "trusted_policy_retrieval",
    }


def _get_timeline(arguments: dict) -> dict:
    timeline = load_incident_timeline(
        arguments["case_id"]
    )

    events = timeline.get("events", [])

    if not isinstance(events, list):
        raise ValueError("Invalid incident timeline")

    if len(events) > MAX_OUTPUT_EVENTS:
        raise ValueError(
            "Incident timeline exceeds tool output limit"
        )

    # Allowlist returned fields; do not expose
    # analyst notes, raw prompts, or evidence bodies.
    permitted = {
        "timestamp",
        "category",
        "event_type",
        "title",
        "status",
        "decision",
        "revision",
        "action",
    }

    return {
        "case_id": arguments["case_id"],
        "event_count": len(events),
        "events": [
            {
                key: value
                for key, value in event.items()
                if key in permitted
            }
            for event in events
            if isinstance(event, dict)
        ],
        "read_only": True,
    }


def _list_plans(arguments: dict) -> dict:
    case_id = arguments["case_id"]

    plans = list_stored_response_plans()

    matching = [
        plan
        for plan in plans
        if plan.get("case_id") == case_id
    ]

    if len(matching) > MAX_OUTPUT_EVENTS:
        raise ValueError(
            "Too many response plans"
        )

    return {
        "case_id": case_id,
        "count": len(matching),
        "plans": [
            {
                "plan_id": plan.get("plan_id"),
                "action": plan.get("action"),
                "risk_level": plan.get("risk_level"),
                "status": plan.get("status"),
                "execution_mode": "simulation_only",
            }
            for plan in matching
        ],
    }


def _propose_response(
    arguments: dict,
    case: dict,
) -> dict:
    """
    Generate an ephemeral proposal.

    No response-plan record is saved.
    No approval is granted.
    No response action is executed.
    """

    plan = create_response_plan(
        case_id=case["case_id"],
        case_status=case["status"],
        action=arguments["action"],
        target=arguments.get("target"),
    )

    return {
        "case_id": case["case_id"],
        "action": plan["action"],
        "risk_level": plan["risk_level"],
        "requires_approval": plan["requires_approval"],
        "policy_decision": plan["policy_decision"],
        "status": plan["status"],
        "execution_mode": "simulation_only",
        "persisted": False,
        "real_action_executed": False,
    }


def dispatch_agent_tool_call(
    tool_name: str,
    arguments: Any,
    context: AgentSecurityContext,
) -> dict[str, Any]:
    """
    Authorize and dispatch one registered agent tool.

    Never accepts a caller-supplied Python function,
    arbitrary module name, or executable command.
    """

    authorization = authorize_agent_tool_call(
        tool_name=tool_name,
        arguments=arguments,
        context=context,
    )

    if not authorization["allowed"]:
        return _blocked(
            authorization["reason"]
        )

    args = authorization["normalized_arguments"]

    handlers = {
        "search_security_policies": _search_policies,
        "get_incident_timeline": _get_timeline,
        "list_response_plans": _list_plans,
    }

    try:
        case = None

        if "case_id" in args:
            case = _find_case(args["case_id"])

            if case is None:
                return _blocked(
                    "Investigation case not found"
                )

        if tool_name == "propose_response_action":
            if case.get("status") not in {
                "open",
                "investigating",
            }:
                return _blocked(
                    "Investigation case is not active"
                )

            data = _propose_response(
                args,
                case,
            )

        else:
            handler = handlers.get(tool_name)

            if handler is None:
                return _blocked(
                    "No registered tool handler"
                )

            data = handler(args)

    except Exception:
        # Do not return exception strings containing
        # local paths, configuration, or internal data.
        return _blocked(
            "Tool unavailable or security validation failed"
        )

    return {
        "allowed": True,
        "decision": "completed",
        "tool_name": tool_name,
        "principal_id": context.principal_id,
        "executed": True,
        "real_action_executed": False,
        "data": data,
    }
