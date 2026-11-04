
import json
from datetime import datetime, timezone
from pathlib import Path

from backend.audit_logger import AUDIT_FILE
from backend.security_monitor import analyze_security_events


MAX_AUDIT_FILE_BYTES = 10 * 1024 * 1024

EVALUATION_EVENT = "ai.security.evaluation"
INTEGRITY_EVENT = "ai.security.document_integrity_failure"


def load_audit_events(
    file_path: Path | None = None,
) -> dict:
    """
    Load validated security audit events.

    Supports existing evaluation events and
    document-integrity failure events.
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
                    raise ValueError(
                        "Event must be a JSON object"
                    )

                event_type = event.get("event_type")

                common_fields = (
                    "timestamp",
                    "event_type",
                    "request_id",
                    "decision",
                )

                if any(
                    not isinstance(event.get(field), str)
                    for field in common_fields
                ):
                    raise ValueError(
                        "Missing or invalid common fields"
                    )

                timestamp = datetime.fromisoformat(
                    event["timestamp"].replace(
                        "Z", "+00:00"
                    )
                )

                if timestamp.tzinfo is None:
                    raise ValueError(
                        "Audit timestamp requires timezone"
                    )

                if event_type == INTEGRITY_EVENT:
                    if (
                        event.get("route") not in {
                            "/chat/rag",
                            "/security/evaluate",
                        }
                        or event.get("stage") not in {
                            "retrieval",
                            "dependency_initialization",
                        }
                        or event["decision"] != "blocked"
                        or event.get("review_required") is not True
                    ):
                        raise ValueError(
                            "Invalid integrity event"
                        )

                    events.append(event)

                elif event_type == EVALUATION_EVENT:
                    if not isinstance(
                        event.get("cited_document"), str
                    ):
                        raise ValueError(
                            "Invalid evaluation document ID"
                        )

                    events.append(event)

                else:
                    # Preserve the old reader's behavior:
                    # unrelated valid events are ignored,
                    # while malformed records are counted.
                    if not isinstance(
                        event.get("cited_document"), str
                    ):
                        raise ValueError(
                            "Invalid unrecognized audit event"
                        )

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
    Run on-demand monitoring against current audit data.

    Integrity events are now loaded, but alert
    detection rules will be added in the next step.
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
