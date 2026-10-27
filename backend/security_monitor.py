
from datetime import datetime, timedelta, timezone


DETECTION_RULES = {
    "AI-MON-001": {
        "name": "Repeated AI evaluation failures",
        "decision": "evaluation_error",
        "threshold": 3,
        "severity": "high",
    },
    "AI-MON-002": {
        "name": "High manual review volume",
        "decision": "review_required",
        "threshold": 4,
        "severity": "medium",
    },
    "AI-MON-003": {
        "name": "Repeated unrecognized document references",
        "document_id": "UNRECOGNIZED",
        "threshold": 2,
        "severity": "medium",
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
    Analyze structured AI security audit events.

    This initial version evaluates one time window.
    It does not continuously monitor live requests.
    """

    if window_minutes <= 0:
        raise ValueError(
            "Monitoring window must be positive"
        )

    parsed_events = []

    for event in events:
        if event.get("event_type") != "ai.security.evaluation":
            continue

        timestamp = parse_timestamp(event["timestamp"])

        parsed_events.append({
            **event,
            "_parsed_timestamp": timestamp,
        })

    if reference_time is None:
        # For offline evaluation, anchor the window
        # to the newest event in the dataset.
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

        if "decision" in rule:
            matching_events = [
                event
                for event in relevant_events
                if event.get("decision") == rule["decision"]
            ]

        else:
            matching_events = [
                event
                for event in relevant_events
                if (
                    event.get("cited_document")
                    == rule["document_id"]
                )
            ]

        # Do not count repeated records for the
        # same request ID more than once.
        unique_events = {}

        for event in matching_events:
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
                "window_minutes": window_minutes,
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
