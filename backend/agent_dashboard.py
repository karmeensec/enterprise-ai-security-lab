
"""
Experiment 58 — Agent Security Dashboard.

Authenticated, read-only view of AI agent activity
and agent-specific security alerts.

Uses Experiment 56's existing monitoring service.
No LLM loading or real response actions.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from dashboard.router import require_dashboard_login
from backend.agent_observability import (
    load_agent_events,
    run_agent_monitor,
)


TEMPLATE_DIRECTORY = (
    Path(__file__).resolve().parent.parent
    / "dashboard"
    / "templates"
)

templates = Jinja2Templates(
    directory=str(TEMPLATE_DIRECTORY)
)

router = APIRouter(
    prefix="/dashboard",
    tags=["Agent Security Dashboard"],
)

MONITORING_WINDOW_MINUTES = 5
MAX_DISPLAY_EVENTS = 50


def build_agent_dashboard_report() -> dict:
    """
    Build a read-only, sanitized dashboard report.

    Detection rules have a fixed five-minute lookback.
    Historical agent events remain visible separately.
    """

    monitor = run_agent_monitor(
        window_minutes=MONITORING_WINDOW_MINUTES
    )

    loaded = load_agent_events()

    monitoring = monitor["monitoring"]

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(
        minutes=MONITORING_WINDOW_MINUTES
    )

    history = []
    active_event_count = 0

    for event in loaded["events"]:
        timestamp = datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        ).astimezone(timezone.utc)

        if window_start <= timestamp <= now:
            active_event_count += 1

        history.append({
            "timestamp": timestamp.isoformat(),
            "request_id": event["request_id"],
            "principal_ref": event["principal_ref"],
            "tool_name": event["tool_name"],
            "decision": event["decision"],
            "reason_category": event["reason_category"],
        })

    history.sort(
        key=lambda event: event["timestamp"],
        reverse=True,
    )

    alerts = []

    for alert in monitoring["alerts"]:
        alerts.append({
            "rule_id": alert["rule_id"],
            "rule_name": alert["rule_name"],
            "severity": alert["severity"],
            "principal_ref": alert["principal_ref"],
            "event_count": alert["event_count"],
            "threshold": alert["threshold"],
            "detected_at": alert["detected_at"],
        })

    alerts.sort(
        key=lambda alert: (
            0 if alert["severity"] == "critical" else
            1 if alert["severity"] == "high" else 2,
            alert["rule_id"],
        )
    )

    return {
        "page_title": "Agent Security Monitoring",
        "monitoring_window": MONITORING_WINDOW_MINUTES,
        "monitoring_mode": "on_demand",
        "total_agent_events": len(loaded["events"]),
        "recent_agent_events": active_event_count,
        "invalid_agent_lines": loaded["invalid_lines"],
        "alert_count": len(alerts),
        "high_severity_count": sum(
            alert["severity"] in {"high", "critical"}
            for alert in alerts
        ),
        "alerts": alerts,
        "events": history[:MAX_DISPLAY_EVENTS],
        "display_limit": MAX_DISPLAY_EVENTS,
        "generated_at": now.isoformat(),
    }


@router.get(
    "/agent-security",
    response_class=HTMLResponse,
)
def agent_security_dashboard(
    request: Request,
    _: str = Depends(require_dashboard_login),
):
    """
    Show agent alerts and recent audit events.

    Authentication reuses the existing SOC dashboard.
    """

    try:
        report = build_agent_dashboard_report()
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Agent security dashboard unavailable",
        ) from exc

    return templates.TemplateResponse(
        request=request,
        name="agent_security.html",
        context=report,
    )
