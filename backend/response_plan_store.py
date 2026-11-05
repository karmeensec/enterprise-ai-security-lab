
"""
Experiment 50.3 — Persistent Response Plan Store.

Stores incident response plans and approval decisions
as revisioned JSONL records.

Simulation only. No real-world response actions are
executed by this module.

Authentication and reviewer authorization are handled
in a later API integration step.
"""

import json
import os
import threading
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from backend.response_approval import (
    ResponseApprovalError,
    review_response_plan,
)
from backend.response_policy_engine import (
    create_response_plan,
)


ROOT = Path(__file__).resolve().parent.parent

RESPONSE_PLAN_FILE = (
    ROOT / "logs" / "response_plans.jsonl"
)

MAX_STORE_BYTES = 5 * 1024 * 1024

_store_lock = threading.RLock()


class ResponseStoreError(ValueError):
    """Invalid or unavailable response-plan storage."""


def _store_path(file_path: Path | None) -> Path:
    return (
        Path(file_path)
        if file_path is not None
        else RESPONSE_PLAN_FILE
    )


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_plan_id(plan_id: str) -> None:
    if not isinstance(plan_id, str):
        raise ResponseStoreError("Invalid plan ID")

    try:
        UUID(plan_id)
    except ValueError as exc:
        raise ResponseStoreError(
            "Invalid plan ID"
        ) from exc


def _read_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    if path.stat().st_size > MAX_STORE_BYTES:
        raise ResponseStoreError(
            "Response-plan store exceeds size limit"
        )

    records = []
    revisions = {}

    try:
        with path.open("r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue

                record = json.loads(line)

                if not isinstance(record, dict):
                    raise ResponseStoreError(
                        "Invalid response-plan record"
                    )

                plan = record.get("plan")

                if not isinstance(plan, dict):
                    raise ResponseStoreError(
                        "Invalid stored response plan"
                    )

                plan_id = plan.get("plan_id")
                _validate_plan_id(plan_id)

                revision = record.get("revision")

                if (
                    type(revision) is not int
                    or revision <= 0
                ):
                    raise ResponseStoreError(
                        "Invalid response-plan revision"
                    )

                expected = revisions.get(plan_id, 0) + 1

                if revision != expected:
                    raise ResponseStoreError(
                        "Inconsistent response-plan history"
                    )

                event_type = record.get("event_type")

                if revision == 1:
                    if (
                        event_type != "plan_created"
                        or plan.get("status") not in {
                            "proposed",
                            "pending_approval",
                        }
                        or plan.get("executed") is not False
                        or plan.get("execution_mode")
                        != "simulation_only"
                    ):
                        raise ResponseStoreError(
                            "Invalid initial plan record"
                        )

                elif event_type != "plan_reviewed":
                    raise ResponseStoreError(
                        "Invalid plan revision event"
                    )

                if not isinstance(
                    record.get("recorded_at"), str
                ):
                    raise ResponseStoreError(
                        "Invalid record timestamp"
                    )

                revisions[plan_id] = revision
                records.append(record)

    except (
        json.JSONDecodeError,
        UnicodeError,
    ) as exc:
        raise ResponseStoreError(
            "Corrupted response-plan store"
        ) from exc

    return records


def _append_record(
    path: Path,
    record: dict[str, Any],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    encoded = json.dumps(
        record,
        ensure_ascii=True,
        separators=(",", ":"),
    ) + "\n"

    current_size = (
        path.stat().st_size
        if path.exists()
        else 0
    )

    if (
        current_size + len(encoded.encode("utf-8"))
        > MAX_STORE_BYTES
    ):
        raise ResponseStoreError(
            "Response-plan store exceeds size limit"
        )

    with path.open("a", encoding="utf-8") as file:
        file.write(encoded)
        file.flush()
        os.fsync(file.fileno())


def _latest_plans(
    records: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    latest = {}

    for record in records:
        plan = record["plan"]
        latest[plan["plan_id"]] = record

    return latest


def create_stored_response_plan(
    case_id: str,
    case_status: str,
    action: str,
    target: str | None = None,
    file_path: Path | None = None,
) -> dict[str, Any]:
    """
    Create and persist a simulation-only response plan.

    IMPORTANT: The caller must obtain case_status
    from the trusted case store, not from browser input.
    """

    path = _store_path(file_path)

    with _store_lock:
        # Fail closed if historical data is corrupted.
        _read_records(path)

        plan = create_response_plan(
            case_id=case_id,
            case_status=case_status,
            action=action,
            target=target,
        )

        record = {
            "event_type": "plan_created",
            "recorded_at": _timestamp(),
            "revision": 1,
            "plan": deepcopy(plan),
        }

        _append_record(path, record)

    return deepcopy(plan)


def get_stored_response_plan(
    plan_id: str,
    file_path: Path | None = None,
) -> dict[str, Any]:
    """Return the most recent version of a plan."""

    _validate_plan_id(plan_id)
    path = _store_path(file_path)

    with _store_lock:
        latest = _latest_plans(
            _read_records(path)
        )

        record = latest.get(plan_id)

        if record is None:
            raise ResponseStoreError(
                "Response plan not found"
            )

        return deepcopy(record["plan"])


def list_stored_response_plans(
    file_path: Path | None = None,
) -> list[dict[str, Any]]:
    """Return one current record per response plan."""

    path = _store_path(file_path)

    with _store_lock:
        latest = _latest_plans(
            _read_records(path)
        )

        return [
            deepcopy(record["plan"])
            for record in latest.values()
        ]


def get_response_plan_history(
    plan_id: str,
    file_path: Path | None = None,
) -> list[dict[str, Any]]:
    """Return all saved revisions for a plan."""

    _validate_plan_id(plan_id)
    path = _store_path(file_path)

    with _store_lock:
        records = _read_records(path)

        history = [
            deepcopy(record)
            for record in records
            if (
                record["plan"]["plan_id"]
                == plan_id
            )
        ]

        if not history:
            raise ResponseStoreError(
                "Response plan not found"
            )

        return history


def review_stored_response_plan(
    plan_id: str,
    reviewer: str,
    decision: str,
    notes: str,
    file_path: Path | None = None,
) -> dict[str, Any]:
    """
    Persist approval or rejection of a response plan.

    The reviewer argument must come from a trusted,
    authenticated server-side identity.

    This function does not grant permissions or
    execute any response action.
    """

    _validate_plan_id(plan_id)
    path = _store_path(file_path)

    with _store_lock:
        latest = _latest_plans(
            _read_records(path)
        )

        previous = latest.get(plan_id)

        if previous is None:
            raise ResponseStoreError(
                "Response plan not found"
            )

        updated = review_response_plan(
            plan=previous["plan"],
            reviewer=reviewer,
            decision=decision,
            notes=notes,
        )

        record = {
            "event_type": "plan_reviewed",
            "recorded_at": _timestamp(),
            "revision": previous["revision"] + 1,
            "plan": deepcopy(updated),
        }

        _append_record(path, record)

    return deepcopy(updated)
