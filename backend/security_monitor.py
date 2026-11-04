
from datetime import datetime, timedelta, timezone


EVALUATION_EVENT = "ai.security.evaluation"
INTEGRITY_EVENT = "ai.security.document_integrity_failure"


DETECTION_RULES = {
    "AI-MON-001": {
        "name": "Repeated AI evaluation failures",
        "event_type": EVALUATION_EVENT,
        "decision": "evaluation_error",
        "threshold": 3,
        "severity": "high",
    },
    "AI-MON-002": {
        "name": "High manual review volume",
        "event_type": EVALUATION_EVENT,
        "decision": "review_required",
        "threshold": 4,
        "severity": "medium",
    },
    "AI-MON-003": {
        "name": "Repeated unrecognized document references",
        "event_type": EVALUATION_EVENT,
        "document_id": "UNRECOGNIZED",
        "threshold": 2,
        "severity": "medium",
    },
    "AI-MON-004": {
        "name": "Knowledge-base integrity failure",
        "event_type": INTEGRITY_EVENT,
        "threshold": 1,
        "severity": "high",
    },
    "AI-MON-005": {
        "name": "Repeated knowledge-base integrity failures",
        "event_type": INTEGRITY_EVENT,
        "threshold": 3,
        "severity": "critical",
        "lookback_minutes": 5,
    },
}


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 audit timestamp."""
    timestamp = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if timestamp.tzinfo is None:
        raise ValueError(
            "Audit timestamps must include a timezone"
        )

    return timestamp.astimezone(timezone.utc)


def analyze_security_events(
    events: list[dict],
    window_minutes: int = 5,
    reference_time: datetime | None = None,
) -> dict:
    """
    Analyze evaluation and document-integrity audit events.

    This is an on-demand detection engine, not
    a continuously running alert delivery service.
    """
    if window_minutes <= 0:
        raise ValueError(
            "Monitoring window must be positive"
        )

    parsed_events = []

    for event in events:
        if event.get("event_type") not in {
            EVALUATION_EVENT,
            INTEGRITY_EVENT,
        }:
            continue

        timestamp = parse_timestamp(event["timestamp"])

        parsed_events.append({
            **event,
            "_parsed_timestamp": timestamp,
        })

    if reference_time is None:
        reference_time = (
            max(
                event["_parsed_timestamp"]
                for event in parsed_events
            )
            if parsed_events
            else datetime.now(timezone.utc)
        )
    else:
        if reference_time.tzinfo is None:
            raise ValueError(
                "Reference time must include a timezone"
            )

        reference_time = reference_time.astimezone(
            timezone.utc
        )

    window_start = reference_time - timedelta(
        minutes=window_minutes
    )

    relevant_events = [
        event
        for event in parsed_events
        if (
            window_start
            <= event["_parsed_timestamp"]
            <= reference_time
        )
    ]

    alerts = []

    for rule_id, rule in DETECTION_RULES.items():
        rule_events = [
            event
            for event in relevant_events
            if event.get("event_type") == rule["event_type"]
        ]

        if "decision" in rule:
            rule_events = [
                event
                for event in rule_events
                if event.get("decision") == rule["decision"]
            ]

        if "document_id" in rule:
            rule_events = [
                event
                for event in rule_events
                if (
                    event.get("cited_document")
                    == rule["document_id"]
                )
            ]

        # AI-MON-005 is limited to the most recent
        # five minutes, even if the caller requests
        # a longer monitoring window.
        if "lookback_minutes" in rule:
            rule_start = reference_time - timedelta(
                minutes=rule["lookback_minutes"]
            )

            rule_events = [
                event
                for event in rule_events
                if event["_parsed_timestamp"] >= rule_start
            ]

        # Deduplicate records by request ID.
        unique_events = {}

        for event in rule_events:
            request_id = event.get("request_id")

            if request_id:
                unique_events[request_id] = event

        count = len(unique_events)

        if count >= rule["threshold"]:
            alerts.append({
                "rule_id": rule_id,
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "status": "triggered",
                "event_count": count,
                "threshold": rule["threshold"],
                "window_minutes": (
                    min(
                        window_minutes,
                        rule["lookback_minutes"],
                    )
                    if "lookback_minutes" in rule
                    else window_minutes
                ),
                "request_ids": list(unique_events),
                "detected_at": reference_time.isoformat(),
            })

    return {
        "reference_time": reference_time.isoformat(),
        "window_start": window_start.isoformat(),
        "window_minutes": window_minutes,
        "events_in_window": len(relevant_events),
        "alert_count": len(alerts),
        "alerts": alerts,
    }
