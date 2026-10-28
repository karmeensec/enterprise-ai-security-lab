
import json
from datetime import datetime, timezone
from pathlib import Path

from backend.audit_logger import AUDIT_FILE
from backend.security_monitor import analyze_security_events


MAX_AUDIT_FILE_BYTES = 10 * 1024 * 1024


def load_audit_events(
    file_path: Path | None = None,
) -> dict:
    """
    Read and validate local JSONL audit events.

    This is a single-file, on-demand monitoring reader,
    not yet a continuous or centralized log collector.
    """
    path = Path(file_path) if file_path is not None else AUDIT_FILE

    if not path.exists():
        return {
            "events": [],
            "valid_events": 0,
            "invalid_lines": 0,
            "file_exists": False,
        }

    if path.stat().st_size > MAX_AUDIT_FILE_BYTES:
        raise ValueError(
            "Audit file exceeds the local monitoring size limit"
        )

    events = []
    invalid_lines = 0

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            try:
                event = json.loads(line)

                if not isinstance(event, dict):
                    raise ValueError("Event must be an object")

                required = (
                    "timestamp",
                    "event_type",
                    "request_id",
                    "decision",
                    "cited_document",
                )

                if any(key not in event for key in required):
                    raise ValueError("Missing required fields")

                if not all(
                    isinstance(event[key], str)
                    for key in required
                ):
                    raise ValueError("Invalid field types")

                timestamp = datetime.fromisoformat(
                    event["timestamp"].replace("Z", "+00:00")
                )

                if timestamp.tzinfo is None:
                    raise ValueError("Timezone is required")

                if event["event_type"] != "ai.security.evaluation":
                    continue

                events.append(event)

            except (
                json.JSONDecodeError,
                ValueError,
                TypeError,
                OverflowError,
            ):
                invalid_lines += 1

    return {
        "events": events,
        "valid_events": len(events),
        "invalid_lines": invalid_lines,
        "file_exists": True,
    }


def run_live_monitor(
    window_minutes: int = 5,
) -> dict:
    """
    Analyze the most recent monitoring window
    using the current UTC time.
    """
    audit_data = load_audit_events()

    monitoring = analyze_security_events(
        audit_data["events"],
        window_minutes=window_minutes,
        reference_time=datetime.now(timezone.utc),
    )

    return {
        "monitoring_mode": "on_demand",
        "audit_file_exists": audit_data["file_exists"],
        "valid_events_loaded": audit_data["valid_events"],
        "invalid_lines": audit_data["invalid_lines"],
        "monitoring": monitoring,
    }
