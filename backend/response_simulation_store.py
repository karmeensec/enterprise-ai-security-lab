
"""
Experiment 50.6 — Persistent Response Simulation History.

Stores the results of simulation-only incident response
actions in a local JSONL file.

Security properties:
- Loads response plans from the trusted plan store.
- Validates eligibility before simulation.
- Prevents duplicate simulation records per plan
  within a single Python process.
- Never performs real response actions.
- Preserves previous simulation records.

This is a local development implementation.
"""

import json
import os
import threading

from copy import deepcopy
from pathlib import Path
from typing import Any
from uuid import UUID

from backend.response_plan_store import (
    get_stored_response_plan,
)
from backend.response_simulator import (
    simulate_response_plan,
)


ROOT = Path(__file__).resolve().parent.parent

SIMULATION_FILE = (
    ROOT / "logs" / "response_simulations.jsonl"
)

MAX_SIMULATION_FILE_BYTES = 5 * 1024 * 1024

_simulation_lock = threading.RLock()


class SimulationStoreError(ValueError):
    """Raised when simulation history is invalid."""


def _path(file_path: Path | None) -> Path:
    return (
        Path(file_path)
        if file_path is not None
        else SIMULATION_FILE
    )


def _validate_uuid(value: Any) -> None:
    if not isinstance(value, str):
        raise SimulationStoreError(
            "Invalid response plan ID"
        )

    try:
        UUID(value)
    except ValueError as exc:
        raise SimulationStoreError(
            "Invalid response plan ID"
        ) from exc


def _read_simulations(
    path: Path,
) -> list[dict[str, Any]]:
    """Read and validate persisted simulation results."""

    if not path.exists():
        return []

    if path.stat().st_size > MAX_SIMULATION_FILE_BYTES:
        raise SimulationStoreError(
            "Simulation history exceeds size limit"
        )

    records = []
    seen_plans = set()
    seen_simulations = set()

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:

            for line in file:
                if not line.strip():
                    continue

                record = json.loads(line)

                if not isinstance(record, dict):
                    raise SimulationStoreError(
                        "Invalid simulation record"
                    )

                plan_id = record.get("plan_id")
                simulation_id = record.get(
                    "simulation_id"
                )

                _validate_uuid(plan_id)

                try:
                    UUID(simulation_id)
                except (TypeError, ValueError) as exc:
                    raise SimulationStoreError(
                        "Invalid simulation identifier"
                    ) from exc

                if plan_id in seen_plans:
                    raise SimulationStoreError(
                        "Duplicate simulation for response plan"
                    )

                if simulation_id in seen_simulations:
                    raise SimulationStoreError(
                        "Duplicate simulation identifier"
                    )

                if (
                    record.get("simulation_status")
                    != "completed"
                    or record.get("execution_mode")
                    != "simulation_only"
                    or record.get("real_action_executed")
                    is not False
                ):
                    raise SimulationStoreError(
                        "Invalid simulation security state"
                    )

                if not isinstance(
                    record.get("simulated_at"), str
                ):
                    raise SimulationStoreError(
                        "Missing simulation timestamp"
                    )

                safeguards = record.get("safeguards")

                if (
                    not isinstance(safeguards, dict)
                    or set(safeguards) != {
                        "shell_execution",
                        "network_requests",
                        "system_modification",
                        "credential_modification",
                    }
                    or any(
                        value is not False
                        for value in safeguards.values()
                    )
                ):
                    raise SimulationStoreError(
                        "Invalid simulation safeguards"
                    )

                seen_plans.add(plan_id)
                seen_simulations.add(simulation_id)
                records.append(record)

    except (
        json.JSONDecodeError,
        UnicodeError,
    ) as exc:
        raise SimulationStoreError(
            "Corrupted simulation history"
        ) from exc

    return records


def _append_simulation(
    path: Path,
    result: dict[str, Any],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    encoded = (
        json.dumps(
            result,
            ensure_ascii=True,
            separators=(",", ":"),
        )
        + "\n"
    )

    existing_size = (
        path.stat().st_size
        if path.exists()
        else 0
    )

    if (
        existing_size + len(encoded.encode("utf-8"))
        > MAX_SIMULATION_FILE_BYTES
    ):
        raise SimulationStoreError(
            "Simulation history exceeds size limit"
        )

    with path.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(encoded)
        file.flush()
        os.fsync(file.fileno())


def simulate_stored_response_plan(
    plan_id: str,
    simulation_file: Path | None = None,
    plan_file: Path | None = None,
) -> dict[str, Any]:
    """
    Simulate an existing stored response plan once.

    The plan is loaded from server-side storage.
    Caller-supplied plan data is never accepted.

    Does not execute real incident response actions.
    """

    _validate_uuid(plan_id)

    path = _path(simulation_file)

    with _simulation_lock:
        existing = _read_simulations(path)

        if any(
            item["plan_id"] == plan_id
            for item in existing
        ):
            raise SimulationStoreError(
                "Response plan has already been simulated"
            )

        plan = get_stored_response_plan(
            plan_id=plan_id,
            file_path=plan_file,
        )

        result = simulate_response_plan(plan)

        _append_simulation(path, result)

        return deepcopy(result)


def get_stored_simulation(
    plan_id: str,
    file_path: Path | None = None,
) -> dict[str, Any]:
    """Retrieve a simulation by its response plan ID."""

    _validate_uuid(plan_id)

    with _simulation_lock:
        records = _read_simulations(
            _path(file_path)
        )

        for record in records:
            if record["plan_id"] == plan_id:
                return deepcopy(record)

    raise SimulationStoreError(
        "Simulation not found"
    )


def list_stored_simulations(
    file_path: Path | None = None,
) -> list[dict[str, Any]]:
    """Return validated simulation history."""

    with _simulation_lock:
        return deepcopy(
            _read_simulations(
                _path(file_path)
            )
        )
