
"""
Experiment 51 — Unified Security Incident Timeline.

Combines investigation case history, security audit
events, and simulated response activity into one
chronological timeline.

Read-only. Does not execute real actions.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID


MAX_CASE_REVISIONS = 100
MAX_AUDIT_EVENTS = 1000
MAX_RESPONSE_EVENTS = 1000

SUPPORTED_AUDIT_TYPES = {
    "ai.security.evaluation",
    "ai.security.document_integrity_failure",
}

ALLOWED_CASE_STATUSES = {
    "open",
    "investigating",
    "resolved",
}


class UnifiedTimelineError(ValueError):
    """Raised when unified timeline data is invalid."""


def _uuid(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise UnifiedTimelineError(
            f"Invalid {name}"
        )

    try:
        return str(UUID(value))
    except ValueError as exc:
        raise UnifiedTimelineError(
            f"Invalid {name}"
        ) from exc


def _time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise UnifiedTimelineError(
            "Invalid timeline timestamp"
        )

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise UnifiedTimelineError(
            "Invalid timeline timestamp"
        ) from exc

    if parsed.tzinfo is None:
        raise UnifiedTimelineError(
            "Timeline timestamps require timezone"
        )

    return parsed.astimezone(timezone.utc)


def build_unified_case_timeline(
    case_history: list[dict[str, Any]],
    response_timeline: dict[str, Any],
    audit_events: list[dict[str, Any]],
) -> dict[str, Any]:

    if not isinstance(case_history, list) or not case_history:
        raise UnifiedTimelineError(
            "Investigation case history is required"
        )

    if len(case_history) > MAX_CASE_REVISIONS:
        raise UnifiedTimelineError(
            "Too many investigation revisions"
        )

    if not isinstance(response_timeline, dict):
        raise UnifiedTimelineError(
            "Invalid response timeline"
        )

    if not isinstance(audit_events, list):
        raise UnifiedTimelineError(
            "Invalid audit events"
        )

    if len(audit_events) > MAX_AUDIT_EVENTS:
        raise UnifiedTimelineError(
            "Too many audit events"
        )

    first = case_history[0]

    if not isinstance(first, dict):
        raise UnifiedTimelineError(
            "Invalid investigation revision"
        )

    case_id = _uuid(
        first.get("case_id"),
        "case ID",
    )

    rule_id = first.get("rule_id")

    if not isinstance(rule_id, str) or not rule_id:
        raise UnifiedTimelineError(
            "Invalid case detection rule"
        )

    request_ids = first.get("request_ids")

    if (
        not isinstance(request_ids, list)
        or not request_ids
        or len(request_ids) > 100
        or not all(
            isinstance(item, str) and item
            for item in request_ids
        )
    ):
        raise UnifiedTimelineError(
            "Invalid case request IDs"
        )

    request_id_set = set(request_ids)

    if _uuid(
        response_timeline.get("case_id"),
        "response timeline case ID",
    ) != case_id:
        raise UnifiedTimelineError(
            "Response timeline belongs to another case"
        )

    response_events = response_timeline.get("events")

    if not isinstance(response_events, list):
        raise UnifiedTimelineError(
            "Invalid response timeline events"
        )

    if len(response_events) > MAX_RESPONSE_EVENTS:
        raise UnifiedTimelineError(
            "Too many response timeline events"
        )

    timeline = []
    expected_revision = 1

    # Investigation history
    for revision in case_history:
        if not isinstance(revision, dict):
            raise UnifiedTimelineError(
                "Invalid investigation revision"
            )

        if _uuid(
            revision.get("case_id"),
            "case revision ID",
        ) != case_id:
            raise UnifiedTimelineError(
                "Mixed investigation cases"
            )

        if (
            revision.get("rule_id") != rule_id
            or revision.get("request_ids") != request_ids
        ):
            raise UnifiedTimelineError(
                "Inconsistent case evidence references"
            )

        number = revision.get("revision")

        if (
            type(number) is not int
            or number != expected_revision
        ):
            raise UnifiedTimelineError(
                "Invalid investigation revision sequence"
            )

        expected_revision += 1

        case_status = revision.get("status")

        if case_status not in ALLOWED_CASE_STATUSES:
            raise UnifiedTimelineError(
                "Invalid investigation status"
            )

        timestamp = _time(
            revision.get("updated_at")
        )

        timeline.append({
            "timestamp": timestamp.isoformat(),
            "category": "investigation",
            "event_type": (
                "case_opened"
                if number == 1
                else "case_updated"
            ),
            "title": (
                "Investigation opened"
                if number == 1
                else "Investigation updated"
            ),
            "case_id": case_id,
            "status": case_status,
            "revision": number,
            "disposition": revision.get("disposition"),
        })

    # Security audit events
    seen_audit_events = set()

    for event in audit_events:
        if not isinstance(event, dict):
            raise UnifiedTimelineError(
                "Invalid audit event"
            )

        event_type = event.get("event_type")
        request_id = event.get("request_id")

        if event_type not in SUPPORTED_AUDIT_TYPES:
            continue

        if request_id not in request_id_set:
            continue

        timestamp = _time(event.get("timestamp"))

        event_key = (
            event_type,
            request_id,
            timestamp.isoformat(),
        )

        if event_key in seen_audit_events:
            continue

        seen_audit_events.add(event_key)

        item = {
            "timestamp": timestamp.isoformat(),
            "category": "security_event",
            "event_type": event_type,
            "title": (
                "Knowledge-base integrity failure"
                if event_type
                == "ai.security.document_integrity_failure"
                else "AI security evaluation"
            ),
            "case_id": case_id,
            "request_id": request_id,
            "decision": event.get("decision"),
        }

        if (
            event_type
            == "ai.security.document_integrity_failure"
        ):
            item["route"] = event.get("route")
            item["stage"] = event.get("stage")
        else:
            item["cited_document"] = (
                event.get("cited_document")
            )

        timeline.append(item)

    # Response activity
    for event in response_events:
        if not isinstance(event, dict):
            raise UnifiedTimelineError(
                "Invalid response event"
            )

        if _uuid(
            event.get("case_id"),
            "response event case ID",
        ) != case_id:
            raise UnifiedTimelineError(
                "Response event belongs to another case"
            )

        if event.get("execution_mode") != "simulation_only":
            raise UnifiedTimelineError(
                "Invalid response execution mode"
            )

        event_type = event.get("event_type")

        if event_type not in {
            "plan_created",
            "plan_reviewed",
            "simulation_completed",
        }:
            raise UnifiedTimelineError(
                "Invalid response event type"
            )

        if (
            event_type == "simulation_completed"
            and event.get("real_action_executed") is not False
        ):
            raise UnifiedTimelineError(
                "Invalid simulation security state"
            )

        timestamp = _time(
            event.get("timestamp")
        )

        timeline.append({
            "timestamp": timestamp.isoformat(),
            "category": "response",
            "event_type": event_type,
            "title": {
                "plan_created": "Response plan created",
                "plan_reviewed": "Response plan reviewed",
                "simulation_completed": (
                    "Response simulation completed"
                ),
            }[event_type],
            "case_id": case_id,
            "plan_id": _uuid(
                event.get("plan_id"),
                "response plan ID",
            ),
            "action": event.get("action"),
            "status": event.get("status"),
            "execution_mode": "simulation_only",
        })

    timeline.sort(
        key=lambda event: (
            event["timestamp"],
            event["category"],
            event["event_type"],
        )
    )

    return {
        "case_id": case_id,
        "rule_id": rule_id,
        "timeline_type": "unified_security_incident",
        "event_count": len(timeline),
        "investigation_event_count": sum(
            event["category"] == "investigation"
            for event in timeline
        ),
        "security_event_count": sum(
            event["category"] == "security_event"
            for event in timeline
        ),
        "response_event_count": sum(
            event["category"] == "response"
            for event in timeline
        ),
        "events": timeline,
        "read_only": True,
        "incident_confirmed": (
            case_history[-1].get("disposition")
            == "confirmed_incident"
        ),
    }
