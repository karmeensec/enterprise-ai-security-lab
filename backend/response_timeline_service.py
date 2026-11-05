
"""
Experiment 51.2 — Stored Response Timeline Service.

Builds a read-only timeline from persisted response-plan
revisions and simulation records.

No real-world response actions are performed.
"""

from pathlib import Path
from uuid import UUID

from backend.response_plan_store import (
    get_response_plan_history,
    list_stored_response_plans,
)
from backend.response_simulation_store import (
    list_stored_simulations,
)
from backend.response_timeline import (
    MAX_TIMELINE_RECORDS,
    ResponseTimelineError,
    build_response_timeline,
)


def load_response_timeline(
    case_id: str,
    plan_file: Path | None = None,
    simulation_file: Path | None = None,
) -> dict:
    """
    Reconstruct a case's response timeline from storage.

    Reads complete revision history, not only the latest
    status of each response plan.

    A future authenticated API must verify that the case
    exists and that the caller may view it.
    """

    if not isinstance(case_id, str):
        raise ResponseTimelineError(
            "Invalid case ID"
        )

    try:
        normalized_case_id = str(UUID(case_id))
    except ValueError as exc:
        raise ResponseTimelineError(
            "Invalid case ID"
        ) from exc

    # These store functions validate their JSONL records
    # and fail closed when stored history is malformed.
    plans = list_stored_response_plans(
        file_path=plan_file,
    )

    matching_plans = [
        plan
        for plan in plans
        if plan.get("case_id") == normalized_case_id
    ]

    plan_records = []

    for plan in matching_plans:
        history = get_response_plan_history(
            plan_id=plan["plan_id"],
            file_path=plan_file,
        )

        plan_records.extend(history)

        if len(plan_records) > MAX_TIMELINE_RECORDS:
            raise ResponseTimelineError(
                "Too many timeline records"
            )

    all_simulations = list_stored_simulations(
        file_path=simulation_file,
    )

    matching_simulations = [
        record
        for record in all_simulations
        if record.get("case_id") == normalized_case_id
    ]

    if (
        len(plan_records) + len(matching_simulations)
        > MAX_TIMELINE_RECORDS
    ):
        raise ResponseTimelineError(
            "Too many timeline records"
        )

    timeline = build_response_timeline(
        case_id=normalized_case_id,
        plan_records=plan_records,
        simulation_records=matching_simulations,
    )

    timeline["source"] = "local_validated_storage"
    timeline["includes_plan_revisions"] = True
    timeline["includes_simulation_history"] = True

    return timeline
