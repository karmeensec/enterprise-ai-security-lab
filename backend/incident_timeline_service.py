
"""
Experiment 51 — Unified Incident Timeline Integration.

Combines trusted local investigation history, audit
events, response plans, approvals, and simulations.

Read-only. Authentication is required when this service
is exposed through an API.
"""

from uuid import UUID

from backend.investigation_records import load_case_history
from backend.log_monitor_service import load_audit_events
from backend.response_timeline_service import (
    load_response_timeline,
)
from backend.unified_case_timeline import (
    build_unified_case_timeline,
)


def load_incident_timeline(case_id: str) -> dict:
    """
    Reconstruct the security lifecycle of an existing
    investigation case from trusted local storage.
    """

    if not isinstance(case_id, str):
        raise ValueError("Invalid investigation case ID")

    try:
        case_id = str(UUID(case_id))
    except ValueError as exc:
        raise ValueError(
            "Invalid investigation case ID"
        ) from exc

    case_history = load_case_history(case_id)

    if not case_history:
        raise ValueError(
            "Investigation case not found"
        )

    response_timeline = load_response_timeline(
        case_id=case_id
    )

    audit_data = load_audit_events()

    timeline = build_unified_case_timeline(
        case_history=case_history,
        response_timeline=response_timeline,
        audit_events=audit_data["events"],
    )

    timeline["source"] = "trusted_local_storage"
    timeline["invalid_audit_lines"] = (
        audit_data["invalid_lines"]
    )
    timeline["simulation_only"] = True

    return timeline
