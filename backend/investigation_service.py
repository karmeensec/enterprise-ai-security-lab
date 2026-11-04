
from typing import Any

from backend.log_monitor_service import load_audit_events


MAX_EVIDENCE_REQUESTS = 100

EVALUATION_EVENT = "ai.security.evaluation"

INTEGRITY_EVENT = (
    "ai.security.document_integrity_failure"
)

INTEGRITY_RULE_IDS = {
    "AI-MON-004",
    "AI-MON-005",
}


def investigate_alert(
    alert: dict[str, Any],
    audit_events: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Correlate security alerts with their audit evidence.

    Supports:
      - AI evaluation alerts
      - Knowledge-base integrity alerts

    This service performs evidence correlation only.
    It does not confirm that an attack occurred.
    """

    rule_id = alert.get("rule_id")
    request_ids = alert.get("request_ids", [])

    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError("Invalid alert rule ID")

    if not isinstance(request_ids, list):
        raise ValueError("Invalid evidence request IDs")

    if len(request_ids) > MAX_EVIDENCE_REQUESTS:
        raise ValueError("Too many evidence request IDs")

    if not all(
        isinstance(request_id, str) and request_id
        for request_id in request_ids
    ):
        raise ValueError("Invalid evidence request ID")

    unique_ids = list(dict.fromkeys(request_ids))
    requested_ids = set(unique_ids)

    expected_event_type = (
        INTEGRITY_EVENT
        if rule_id in INTEGRITY_RULE_IDS
        else EVALUATION_EVENT
    )

    evidence_by_id = {}

    for event in audit_events:
        if event.get("event_type") != expected_event_type:
            continue

        request_id = event.get("request_id")

        if request_id not in requested_ids:
            continue

        if expected_event_type == INTEGRITY_EVENT:
            if (
                event.get("route") not in {
                    "/chat/rag",
                    "/security/evaluate",
                }
                or event.get("stage") not in {
                    "retrieval",
                    "dependency_initialization",
                }
                or event.get("decision") != "blocked"
                or event.get("review_required") is not True
            ):
                continue

            # Only include approved, non-sensitive
            # integrity-event metadata.
            evidence_by_id[request_id] = {
                "timestamp": event.get("timestamp"),
                "request_id": request_id,
                "event_type": INTEGRITY_EVENT,
                "route": event["route"],
                "stage": event["stage"],
                "decision": "blocked",
                "review_required": True,
            }

        else:
            # Preserve the existing evidence structure
            # for ordinary AI evaluation alerts.
            evidence_by_id[request_id] = {
                "timestamp": event.get("timestamp"),
                "request_id": request_id,
                "cited_document": event.get("cited_document"),
                "decision": event.get("decision"),
                "review_required": event.get("review_required"),
                "duration_ms": event.get("duration_ms"),
            }

    evidence = [
        evidence_by_id[request_id]
        for request_id in unique_ids
        if request_id in evidence_by_id
    ]

    missing_ids = [
        request_id
        for request_id in unique_ids
        if request_id not in evidence_by_id
    ]

    if expected_event_type == INTEGRITY_EVENT:
        investigation_note = (
            "Document-integrity failures were detected. "
            "Review the affected routes, timestamps, "
            "and deployment history. Determine whether "
            "the cause was unauthorized modification, "
            "an operational error, or another issue."
        )
    else:
        investigation_note = (
            "Automated evidence correlation only. "
            "An analyst must determine whether the "
            "activity represents a security incident."
        )

    return {
        "rule_id": rule_id,
        "rule_name": alert.get("rule_name"),
        "severity": alert.get("severity"),
        "alert_status": "requires_investigation",
        "evidence_expected": len(unique_ids),
        "evidence_found": len(evidence),
        "evidence_missing": len(missing_ids),
        "events": evidence,
        "missing_request_ids": missing_ids,
        "investigation_note": investigation_note,
    }


def investigate_alert_from_logs(
    alert: dict[str, Any],
) -> dict[str, Any]:
    """
    Correlate a detection alert against the
    validated local security audit log.
    """

    audit_data = load_audit_events()

    result = investigate_alert(
        alert=alert,
        audit_events=audit_data["events"],
    )

    result["invalid_audit_lines"] = (
        audit_data["invalid_lines"]
    )

    return result
