
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock


ROOT = Path(__file__).resolve().parent.parent
AUDIT_DIRECTORY = ROOT / "logs"
AUDIT_FILE = AUDIT_DIRECTORY / "security_audit.jsonl"

logger = logging.getLogger("enterprise_ai_security_lab.audit")

_write_lock = Lock()

ALLOWED_DECISIONS = {
    "supported_by_checks",
    "unsupported_by_checks",
    "review_required",
    "evaluation_error",
}


def record_security_evaluation(
    request_id: str,
    cited_document: str,
    decision: str,
    review_required: bool,
    duration_ms: float,
) -> dict:
    """
    Record one structured AI security evaluation event.

    Intentionally excludes user prompts, generated
    answers, policy content, secrets, and user identities.
    """

    if decision not in ALLOWED_DECISIONS:
        raise ValueError("Invalid security decision")

    if not isinstance(review_required, bool):
        raise ValueError("review_required must be boolean")

    if not isinstance(duration_ms, (int, float)):
        raise ValueError("duration_ms must be numeric")

    if not 0 <= duration_ms < float("inf"):
        raise ValueError("Invalid evaluation duration")

    # Limit uncontrolled metadata before writing to disk.
    if not isinstance(request_id, str):
        raise ValueError("Invalid request ID")

    if not isinstance(cited_document, str):
        raise ValueError("Invalid document ID")

    if len(request_id) > 128:
        raise ValueError("Request ID too long")

    import re

    safe_document_id = cited_document.upper().strip()

    if not re.fullmatch(r"POL-\d{3}", safe_document_id):
        safe_document_id = "UNRECOGNIZED"

    event = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "event_type": "ai.security.evaluation",
        "request_id": request_id,
        "cited_document": safe_document_id,
        "decision": decision,
        "review_required": review_required,
        "duration_ms": round(duration_ms, 2),
    }

    serialized = json.dumps(
        event,
        ensure_ascii=False,
        allow_nan=False,
    )

    AUDIT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Thread-safe for writers inside this Python process.
    # Cross-process locking will be a later improvement.
    with _write_lock:
        with AUDIT_FILE.open(
            "a",
            encoding="utf-8",
        ) as file:
            file.write(serialized + "\n")

    logger.info(
        "Security audit event recorded request_id=%s",
        request_id,
    )

    return event
