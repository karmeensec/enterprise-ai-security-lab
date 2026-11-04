"""Local, append-only analyst investigation records (development lab).

This is not a tamper-proof case database or multi-worker transaction system.
Do not put secrets or full user prompts in analyst notes.
"""

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CASE_FILE = ROOT / "logs" / "investigation_cases.jsonl"
MAX_CASE_FILE_BYTES = 5 * 1024 * 1024
MAX_NOTES_LENGTH = 2000
MAX_REQUEST_IDS = 100
_LOCK = threading.RLock()

ALLOWED_STATUSES = {"open", "investigating", "resolved"}
ALLOWED_DISPOSITIONS = {
    "pending",
    "benign",
    "confirmed_incident",
    "inconclusive",
}


def _text(value: Any, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Invalid {name}")
    value = value.strip()
    if len(value) > maximum or any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise ValueError(f"Invalid {name}")
    return value


def _validate_notes(notes: str) -> str:
    if not isinstance(notes, str) or len(notes) > MAX_NOTES_LENGTH:
        raise ValueError("Invalid analyst notes")
    if any(ord(c) < 32 and c not in "\n\t" for c in notes):
        raise ValueError("Invalid analyst notes")
    return notes


def _path(file_path: Path | None) -> Path:
    return Path(file_path) if file_path is not None else DEFAULT_CASE_FILE


def _read_unlocked(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if path.stat().st_size > MAX_CASE_FILE_BYTES:
        raise ValueError("Investigation history exceeds size limit")
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError("Invalid investigation history") from exc
            if not isinstance(row, dict) or not all(
                key in row for key in ("case_id", "status", "updated_at", "revision")
            ):
                raise ValueError("Invalid investigation history")
            rows.append(row)
    return rows


def _append_unlocked(path: Path, record: dict[str, Any]) -> None:
    encoded = json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
    existing_size = path.stat().st_size if path.exists() else 0
    if existing_size + len(encoded.encode("utf-8")) > MAX_CASE_FILE_BYTES:
        raise ValueError("Investigation history exceeds size limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(encoded)
        handle.flush()


def load_cases(file_path: Path | None = None) -> list[dict[str, Any]]:
    """Return latest revision of each case, without modifying the history."""
    with _LOCK:
        rows = _read_unlocked(_path(file_path))
    latest = {}
    for row in rows:
        latest[row["case_id"]] = row
    return list(latest.values())


def load_case_history(case_id: str, file_path: Path | None = None) -> list[dict[str, Any]]:
    case_id = _text(case_id, "case ID", 36)
    with _LOCK:
        return [
            row for row in _read_unlocked(_path(file_path))
            if row["case_id"] == case_id
        ]


def create_case(
    alert: dict[str, Any],
    analyst: str,
    notes: str = "",
    file_path: Path | None = None,
) -> dict[str, Any]:
    """Open a case for an observed alert. This does not confirm an incident."""
    if not isinstance(alert, dict):
        raise ValueError("Invalid alert")
    rule_id = _text(alert.get("rule_id"), "alert rule ID", 64)
    analyst = _text(analyst, "analyst", 100)
    notes = _validate_notes(notes)
    request_ids = alert.get("request_ids")
    if not isinstance(request_ids, list) or not request_ids or len(request_ids) > MAX_REQUEST_IDS:
        raise ValueError("Invalid alert request IDs")
    if not all(isinstance(item, str) and 0 < len(item) <= 128 for item in request_ids):
        raise ValueError("Invalid alert request IDs")
    unique_ids = list(dict.fromkeys(request_ids))
    now = datetime.now(timezone.utc).isoformat()
    record = {
        "case_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "request_ids": unique_ids,
        "status": "open",
        "disposition": "pending",
        "analyst": analyst,
        "notes": notes,
        "created_at": now,
        "updated_at": now,
        "revision": 1,
    }
    with _LOCK:
        path = _path(file_path)
        _read_unlocked(path)  # Fail closed if existing history is malformed.
        _append_unlocked(path, record)
    return record.copy()


def update_case(
    case_id: str,
    analyst: str,
    status: str,
    disposition: str = "pending",
    notes: str = "",
    file_path: Path | None = None,
) -> dict[str, Any]:
    """Append a new case revision after validating the status transition."""
    case_id = _text(case_id, "case ID", 36)
    analyst = _text(analyst, "analyst", 100)
    notes = _validate_notes(notes)
    if status not in ALLOWED_STATUSES:
        raise ValueError("Invalid investigation status")
    if disposition not in ALLOWED_DISPOSITIONS:
        raise ValueError("Invalid investigation disposition")
    if (status == "resolved") != (disposition != "pending"):
        raise ValueError("Disposition must be final only when resolved")

    with _LOCK:
        path = _path(file_path)
        matches = [row for row in _read_unlocked(path) if row["case_id"] == case_id]
        if not matches:
            raise ValueError("Investigation case not found")
        previous = matches[-1]
        allowed_next = {"open": "investigating", "investigating": "resolved"}
        if allowed_next.get(previous["status"]) != status:
            raise ValueError("Invalid investigation status transition")
        record = {
            **previous,
            "status": status,
            "disposition": disposition,
            "analyst": analyst,
            "notes": notes,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "revision": previous["revision"] + 1,
        }
        _append_unlocked(path, record)
    return record.copy()
