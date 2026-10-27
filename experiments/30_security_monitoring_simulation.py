
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.security_monitor import analyze_security_events


ROOT = Path(__file__).resolve().parent.parent
OUTPUT_FILE = ROOT / "results" / "30_security_monitoring.json"


def create_event(
    request_id,
    timestamp,
    decision,
    cited_document="POL-005",
):
    return {
        "timestamp": timestamp.isoformat(),
        "event_type": "ai.security.evaluation",
        "request_id": request_id,
        "cited_document": cited_document,
        "decision": decision,
        "review_required": decision != "supported_by_checks",
        "duration_ms": 125.0,
    }


def main():
    print("=== Experiment 30: Security Monitoring ===")

    now = datetime.now(timezone.utc)
    events = []

    # Normal activity
    for index in range(3):
        events.append(
            create_event(
                f"normal-{index}",
                now - timedelta(minutes=4),
                "supported_by_checks",
            )
        )

    # Rule AI-MON-001: repeated evaluation errors
    for index in range(3):
        events.append(
            create_event(
                f"error-{index}",
                now - timedelta(minutes=3),
                "evaluation_error",
            )
        )

    # Rule AI-MON-002: high manual-review volume
    for index in range(4):
        events.append(
            create_event(
                f"review-{index}",
                now - timedelta(minutes=2),
                "review_required",
            )
        )

    # Rule AI-MON-003: unrecognized policy references
    for index in range(2):
        events.append(
            create_event(
                f"unknown-{index}",
                now - timedelta(minutes=1),
                "review_required",
                "UNRECOGNIZED",
            )
        )

    result = analyze_security_events(
        events,
        window_minutes=5,
        reference_time=now,
    )

    report = {
        "experiment": "30_security_monitoring",
        "scenario": "Synthetic enterprise AI audit events",
        "event_count": len(events),
        "monitoring_result": result,
    }

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print(f"\nEvents analyzed: {len(events)}")
    print(f"Alerts triggered: {result['alert_count']}")

    for alert in result["alerts"]:
        print(f"\nRule: {alert['rule_id']}")
        print(f"Name: {alert['rule_name']}")
        print(f"Severity: {alert['severity']}")
        print(f"Matching events: {alert['event_count']}")
        print(f"Request IDs: {alert['request_ids']}")

    print(f"\nReport saved: {OUTPUT_FILE}")
    print("Experiment 30 completed!")


if __name__ == "__main__":
    main()
