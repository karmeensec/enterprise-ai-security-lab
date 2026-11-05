
"""
Experiment 56 — AI Agent Security Observability.

Uses the existing security audit JSONL file.

Provides:
- Monitored agent execution
- Structured agent activity events
- Principal pseudonymization
- Bounded audit event loading
- Agent abuse detection

Does not store raw prompts, model responses,
tool arguments, targets, or case identifiers.

Monitoring is on-demand, not continuous.
"""

import hashlib
import hmac
import json
import os
import secrets
import uuid

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from backend import audit_logger
from backend.agent_tool_security import AgentSecurityContext
from backend.qwen_security_agent import run_security_agent


AGENT_EVENT_TYPE = "ai.security.agent_tool_activity"
MAX_AUDIT_FILE_BYTES = 10 * 1024 * 1024

# Process-local fallback. For stable correlation across
# restarts, configure AEGIS_AUDIT_PSEUDONYM_KEY.
_PROCESS_KEY = secrets.token_bytes(32)

KNOWN_TOOLS = {
    "search_security_policies",
    "get_incident_timeline",
    "list_response_plans",
    "propose_response_action",
}

REASON_CATEGORIES = {
    "Case access denied": "case_access_denied",
    "Tool is not registered": "unregistered_tool",
    "Tool is not in the agent allowlist": "unregistered_tool",
    "Unexpected tool arguments": "invalid_arguments",
    "Missing required tool arguments": "invalid_arguments",
    "Invalid case identifier": "invalid_arguments",
    "Invalid response target": "invalid_arguments",
    "Unsupported response action": "invalid_arguments",
    "Model did not produce a valid tool proposal": (
        "invalid_model_proposal"
    ),
}


def _principal_reference(principal_id: str) -> str:
    configured = os.environ.get(
        "AEGIS_AUDIT_PSEUDONYM_KEY"
    )

    key = (
        configured.encode("utf-8")
        if configured
        else _PROCESS_KEY
    )

    return hmac.new(
        key,
        principal_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:24]


def _reason_category(reason: Any) -> str:
    if not isinstance(reason, str):
        return "none"

    return REASON_CATEGORIES.get(
        reason,
        "other_denial",
    )


def record_agent_activity(
    result: dict,
    context: AgentSecurityContext,
    file_path: Path | None = None,
) -> dict:
    """
    Write one sanitized agent activity event.

    Reuses the existing audit logger's in-process lock.
    """

    if not isinstance(result, dict):
        raise ValueError("Invalid agent result")

    if not isinstance(context, AgentSecurityContext):
        raise ValueError("Invalid trusted context")

    if (
        not isinstance(context.principal_id, str)
        or not context.principal_id.strip()
    ):
        raise ValueError("Invalid principal")

    allowed = result.get("allowed")

    if type(allowed) is not bool:
        raise ValueError("Invalid authorization decision")

    if result.get("real_action_executed") is not False:
        raise ValueError(
            "Unexpected real-action execution state"
        )

    tool_name = result.get("tool_name")

    if tool_name is None:
        safe_tool = "none"
    elif tool_name in KNOWN_TOOLS:
        safe_tool = tool_name
    else:
        safe_tool = "unregistered"

    event = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "event_type": AGENT_EVENT_TYPE,
        "request_id": str(uuid.uuid4()),
        "principal_ref": _principal_reference(
            context.principal_id
        ),
        "tool_name": safe_tool,
        "decision": (
            "allowed" if allowed else "blocked"
        ),
        "reason_category": (
            "none"
            if allowed
            else _reason_category(result.get("reason"))
        ),
        "real_action_executed": False,
    }

    serialized = json.dumps(
        event,
        allow_nan=False,
    )

    path = (
        Path(file_path)
        if file_path is not None
        else audit_logger.AUDIT_FILE
    )

    with audit_logger._write_lock:
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with path.open(
            "a",
            encoding="utf-8",
        ) as handle:
            handle.write(serialized + "\n")

    return event


def run_monitored_security_agent(
    question: str,
    context: AgentSecurityContext,
    llm_service=None,
    audit_file: Path | None = None,
) -> dict:
    """
    Monitored entrypoint for operational agent calls.

    The caller must supply a trusted, server-derived
    security context.

    Audit write failures propagate: callers must not
    treat an unrecorded request as successful.
    """

    result = run_security_agent(
        question=question,
        context=context,
        llm_service=llm_service,
    )

    record_agent_activity(
        result=result,
        context=context,
        file_path=audit_file,
    )

    return result


def load_agent_events(
    file_path: Path | None = None,
) -> dict:
    """
    Read agent events from the shared audit file.

    Other recognized legacy event types are ignored.
    Invalid agent records are counted and excluded.
    """

    path = (
        Path(file_path)
        if file_path is not None
        else audit_logger.AUDIT_FILE
    )

    if not path.exists():
        return {
            "events": [],
            "invalid_lines": 0,
            "file_exists": False,
        }

    if path.stat().st_size > MAX_AUDIT_FILE_BYTES:
        raise ValueError(
            "Audit file exceeds monitoring size limit"
        )

    events = []
    invalid_lines = 0

    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:
        for line in handle:
            if not line.strip():
                continue

            try:
                event = json.loads(line)

                if not isinstance(event, dict):
                    raise ValueError(
                        "Invalid audit record"
                    )

                if event.get("event_type") != AGENT_EVENT_TYPE:
                    continue

                timestamp = datetime.fromisoformat(
                    event["timestamp"].replace(
                        "Z",
                        "+00:00",
                    )
                )

                if timestamp.tzinfo is None:
                    raise ValueError(
                        "Missing audit timezone"
                    )

                uuid.UUID(event["request_id"])

                principal = event["principal_ref"]

                if (
                    not isinstance(principal, str)
                    or len(principal) != 24
                    or any(
                        char not in "0123456789abcdef"
                        for char in principal
                    )
                ):
                    raise ValueError(
                        "Invalid principal reference"
                    )

                if event["tool_name"] not in (
                    KNOWN_TOOLS
                    | {"none", "unregistered"}
                ):
                    raise ValueError(
                        "Invalid tool name"
                    )

                if event["decision"] not in {
                    "allowed",
                    "blocked",
                }:
                    raise ValueError(
                        "Invalid decision"
                    )

                if not isinstance(
                    event.get("reason_category"),
                    str,
                ):
                    raise ValueError(
                        "Invalid reason category"
                    )

                if (
                    event.get("real_action_executed")
                    is not False
                ):
                    raise ValueError(
                        "Unexpected execution state"
                    )

                events.append(event)

            except (
                KeyError,
                TypeError,
                ValueError,
                OverflowError,
                json.JSONDecodeError,
            ):
                invalid_lines += 1

    return {
        "events": events,
        "invalid_lines": invalid_lines,
        "file_exists": True,
    }


def analyze_agent_events(
    events: list[dict],
    window_minutes: int = 5,
    reference_time: datetime | None = None,
) -> dict:
    """
    Correlate agent tool failures by principal.

    AI-MON-006: >=3 denied requests in five minutes
    AI-MON-007: Unauthorized case access
    AI-MON-008: Unregistered tool proposal
    """

    if (
        type(window_minutes) is not int
        or window_minutes <= 0
    ):
        raise ValueError(
            "Monitoring window must be positive"
        )

    if reference_time is None:
        reference_time = datetime.now(
            timezone.utc
        )

    if reference_time.tzinfo is None:
        raise ValueError(
            "Reference time must be timezone-aware"
        )

    reference_time = reference_time.astimezone(
        timezone.utc
    )

    start = reference_time - timedelta(
        minutes=min(window_minutes, 5)
    )

    grouped = defaultdict(list)

    for event in events:
        if event.get("event_type") != AGENT_EVENT_TYPE:
            continue

        timestamp = datetime.fromisoformat(
            event["timestamp"].replace(
                "Z",
                "+00:00",
            )
        )

        if timestamp.tzinfo is None:
            raise ValueError(
                "Invalid event timestamp"
            )

        timestamp = timestamp.astimezone(
            timezone.utc
        )

        if start <= timestamp <= reference_time:
            grouped[event["principal_ref"]].append(
                event
            )

    alerts = []

    rules = (
        (
            "AI-MON-006",
            "Repeated agent authorization denials",
            "high",
            3,
            lambda event: (
                event["decision"] == "blocked"
            ),
        ),
        (
            "AI-MON-007",
            "Unauthorized incident case access",
            "high",
            1,
            lambda event: (
                event["reason_category"]
                == "case_access_denied"
            ),
        ),
        (
            "AI-MON-008",
            "Unregistered agent tool proposal",
            "medium",
            1,
            lambda event: (
                event["tool_name"] == "unregistered"
                or event["reason_category"]
                == "unregistered_tool"
            ),
        ),
    )

    for principal, principal_events in grouped.items():
        for (
            rule_id,
            rule_name,
            severity,
            threshold,
            predicate,
        ) in rules:
            matching = {
                event["request_id"]: event
                for event in principal_events
                if predicate(event)
            }

            if len(matching) < threshold:
                continue

            alerts.append({
                "rule_id": rule_id,
                "rule_name": rule_name,
                "severity": severity,
                "status": "triggered",
                "principal_ref": principal,
                "event_count": len(matching),
                "threshold": threshold,
                "window_minutes": min(
                    window_minutes,
                    5,
                ),
                "request_ids": list(matching),
                "detected_at": (
                    reference_time.isoformat()
                ),
            })

    return {
        "monitoring_mode": "on_demand",
        "reference_time": reference_time.isoformat(),
        "window_minutes": min(
            window_minutes,
            5,
        ),
        "principal_count": len(grouped),
        "alert_count": len(alerts),
        "alerts": alerts,
    }


def run_agent_monitor(
    window_minutes: int = 5,
    file_path: Path | None = None,
) -> dict:
    """
    Analyze agent events in the existing audit file.
    """

    loaded = load_agent_events(
        file_path=file_path
    )

    monitoring = analyze_agent_events(
        loaded["events"],
        window_minutes=window_minutes,
    )

    return {
        "audit_file_exists": loaded["file_exists"],
        "agent_events_loaded": len(
            loaded["events"]
        ),
        "invalid_lines": loaded["invalid_lines"],
        "monitoring": monitoring,
    }
