
"""
Experiment 51.1 — Security Response Timeline.

Correlates response-plan revisions with simulation
history for one investigation case.

Security:
- Read-only.
- Does not execute response actions.
- Does not expose targets, approval notes, or secrets.
- Requires timezone-aware timestamps.
- Limits the number of processed records.

The authenticated API will load records from trusted
server-side storage in a later step.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID


MAX_TIMELINE_RECORDS = 1000


class ResponseTimelineError(ValueError):
    """Invalid response timeline data."""


def _validate_uuid(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ResponseTimelineError(
            f"Invalid {label}"
        )

    try:
        return str(UUID(value))
    except ValueError as exc:
        raise ResponseTimelineError(
            f"Invalid {label}"
        ) from exc


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ResponseTimelineError(
            "Invalid timeline timestamp"
        )

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ResponseTimelineError(
            "Invalid timeline timestamp"
        ) from exc

    if parsed.tzinfo is None:
        raise ResponseTimelineError(
            "Timeline timestamp requires timezone"
        )

    return parsed.astimezone(timezone.utc)


def build_response_timeline(
    case_id: str,
    plan_records: list[dict[str, Any]],
    simulation_records: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Build a chronological response timeline for one case.

    plan_records are revision records from the response
    plan store, not just current plan snapshots.

    simulation_records are persisted simulation results.

    Records belonging to another case are excluded.
    """

    case_id = _validate_uuid(
        case_id,
        "case ID",
    )

    if (
        not isinstance(plan_records, list)
        or not isinstance(simulation_records, list)
    ):
        raise ResponseTimelineError(
            "Timeline sources must be lists"
        )

    if (
        len(plan_records) + len(simulation_records)
        > MAX_TIMELINE_RECORDS
    ):
        raise ResponseTimelineError(
            "Too many timeline records"
        )

    timeline = []
    known_plan_ids = set()

    for record in plan_records:
        if not isinstance(record, dict):
            raise ResponseTimelineError(
                "Invalid plan revision record"
            )

        plan = record.get("plan")

        if not isinstance(plan, dict):
            raise ResponseTimelineError(
                "Invalid plan revision record"
            )

        record_case_id = _validate_uuid(
            plan.get("case_id"),
            "plan case ID",
        )

        if record_case_id != case_id:
            continue

        plan_id = _validate_uuid(
            plan.get("plan_id"),
            "plan ID",
        )

        event_type = record.get("event_type")

        if event_type not in {
            "plan_created",
            "plan_reviewed",
        }:
            raise ResponseTimelineError(
                "Unsupported plan history event"
            )

        revision = record.get("revision")

        if type(revision) is not int or revision < 1:
            raise ResponseTimelineError(
                "Invalid plan revision"
            )

        recorded_at = _parse_time(
            record.get("recorded_at")
        )

        known_plan_ids.add(plan_id)

        if event_type == "plan_created":
            title = "Response plan created"
        else:
            title = "Response plan reviewed"

        timeline.append({
            "timestamp": recorded_at.isoformat(),
            "event_type": event_type,
            "title": title,
            "case_id": case_id,
            "plan_id": plan_id,
            "action": plan.get("action"),
            "status": plan.get("status"),
            "revision": revision,
            "execution_mode": "simulation_only",
        })

    for record in simulation_records:
        if not isinstance(record, dict):
            raise ResponseTimelineError(
                "Invalid simulation record"
            )

        record_case_id = _validate_uuid(
            record.get("case_id"),
            "simulation case ID",
        )

        if record_case_id != case_id:
            continue

        plan_id = _validate_uuid(
            record.get("plan_id"),
            "simulation plan ID",
        )

        # A simulation must be linked to a plan
        # present in this case's supplied history.
        if plan_id not in known_plan_ids:
            raise ResponseTimelineError(
                "Simulation has no matching response plan"
            )

        if (
            record.get("execution_mode")
            != "simulation_only"
            or record.get("real_action_executed")
            is not False
        ):
            raise ResponseTimelineError(
                "Invalid simulation security state"
            )

        simulated_at = _parse_time(
            record.get("simulated_at")
        )

        simulation_id = _validate_uuid(
            record.get("simulation_id"),
            "simulation ID",
        )

        timeline.append({
            "timestamp": simulated_at.isoformat(),
            "event_type": "simulation_completed",
            "title": "Response simulation completed",
            "case_id": case_id,
            "plan_id": plan_id,
            "simulation_id": simulation_id,
            "action": record.get("action"),
            "status": record.get(
                "simulation_status"
            ),
            "execution_mode": "simulation_only",
            "real_action_executed": False,
        })

    timeline.sort(
        key=lambda event: (
            event["timestamp"],
            event["event_type"],
            event["plan_id"],
        )
    )

    return {
        "case_id": case_id,
        "timeline_type": "response_activity",
        "event_count": len(timeline),
        "plan_count": len(known_plan_ids),
        "events": timeline,
        "read_only": True,
    }
