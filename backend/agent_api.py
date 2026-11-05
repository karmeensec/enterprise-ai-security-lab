
"""
Experiment 57 — Authenticated AI Agent API.

Reuses existing dashboard HTTP Basic authentication.

Security boundaries:
- No client-supplied roles or permissions
- Server-configured case allowlist
- No case access by default
- Cross-origin write protection
- Monitored agent execution
- No real response-action execution

Development-only authentication architecture.
Use TLS and proper identity management for production.
"""

import json
import os
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
)
from pydantic import BaseModel, ConfigDict, Field

from backend.agent_observability import (
    run_agent_monitor,
    run_monitored_security_agent,
)
from backend.agent_tool_security import (
    AgentSecurityContext,
)
from dashboard.router import (
    require_case_write_request,
    require_dashboard_login,
)


router = APIRouter(
    prefix="/agent",
    tags=["AI Security Agent"],
)


class AgentChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question: str = Field(
        min_length=1,
        max_length=1000,
    )


def _trusted_agent_context(
    username: str,
) -> AgentSecurityContext:
    """
    Construct permissions exclusively from
    authenticated server-side configuration.

    AGENT_CASE_ACCESS_JSON example:

    {"analyst1": ["case-uuid-1", "case-uuid-2"]}

    An empty list grants policy-search access,
    but no investigation-case access.
    """

    raw_config = os.environ.get(
        "AGENT_CASE_ACCESS_JSON"
    )

    if not raw_config:
        raise HTTPException(
            status_code=503,
            detail="Agent permissions are not configured",
        )

    try:
        permissions = json.loads(raw_config)

        if not isinstance(permissions, dict):
            raise ValueError("Invalid permission map")

        if username not in permissions:
            raise HTTPException(
                status_code=403,
                detail="Agent access not granted",
            )

        case_ids = permissions[username]

        if (
            not isinstance(case_ids, list)
            or len(case_ids) > 100
        ):
            raise ValueError("Invalid case permissions")

        authorized = set()

        for case_id in case_ids:
            if not isinstance(case_id, str):
                raise ValueError(
                    "Invalid configured case identifier"
                )

            normalized = str(UUID(case_id))

            # Require canonical identifiers to avoid
            # inconsistencies between permission checks.
            if normalized != case_id:
                raise ValueError(
                    "Noncanonical case identifier"
                )

            authorized.add(normalized)

    except HTTPException:
        raise

    except (ValueError, TypeError):
        raise HTTPException(
            status_code=503,
            detail="Agent permissions configuration invalid",
        )

    return AgentSecurityContext(
        principal_id=username,
        role="analyst",
        authorized_case_ids=frozenset(authorized),
    )


@router.post("/chat")
def agent_chat(
    payload: AgentChatRequest,
    request: Request,
    username: str = Depends(require_dashboard_login),
):
    """
    Run one authenticated, audited AI agent request.

    The request accepts only a question.
    It cannot set role, permissions, or tool execution.
    """

    require_case_write_request(request)

    context = _trusted_agent_context(username)

    try:
        result = run_monitored_security_agent(
            question=payload.question,
            context=context,
        )

    except Exception:
        # Includes model failures, storage failures,
        # and unexpected dispatcher errors.
        # An audit failure must not return success.
        raise HTTPException(
            status_code=503,
            detail="AI agent temporarily unavailable",
        )

    if not isinstance(result, dict):
        raise HTTPException(
            status_code=503,
            detail="Invalid AI agent result",
        )

    if result.get("real_action_executed") is not False:
        raise HTTPException(
            status_code=503,
            detail="Invalid AI agent execution state",
        )

    return {
        "request_id": request.state.request_id,
        "status": result.get("status"),
        "allowed": result.get("allowed"),
        "reason": result.get("reason"),
        "tool_name": result.get("tool_name"),
        "tool_result": result.get("tool_result"),
        "response_source": result.get(
            "response_source"
        ),
        "real_action_executed": False,
    }


@router.get("/monitor")
def agent_monitor(
    window_minutes: int = Query(
        default=5,
        ge=1,
        le=60,
    ),
    username: str = Depends(require_dashboard_login),
):
    """
    Read agent security alerts.

    Requires dashboard authentication and explicit
    agent access configuration.
    """

    _trusted_agent_context(username)

    try:
        return run_agent_monitor(
            window_minutes=window_minutes,
        )

    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Agent monitoring temporarily unavailable",
        )
