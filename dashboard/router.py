
import os
import secrets
from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    status,
)
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

from backend.log_monitor_service import run_live_monitor

from backend.security_monitor import DETECTION_RULES
from backend.log_monitor_service import load_audit_events

from fastapi import Query


BASE_DIR = Path(__file__).resolve().parent

templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates")
)

security = HTTPBasic()

router = APIRouter(
    prefix="/dashboard",
    tags=["Security Dashboard"],
)


def require_dashboard_login(
    credentials: HTTPBasicCredentials = Depends(security),
):
    expected_user = os.environ.get("DASHBOARD_USERNAME")
    expected_password = os.environ.get("DASHBOARD_PASSWORD")

    if not expected_user or not expected_password:
        raise HTTPException(
            status_code=503,
            detail="Dashboard authentication is not configured",
        )

    valid_user = secrets.compare_digest(
        credentials.username.encode("utf-8"),
        expected_user.encode("utf-8"),
    )
    valid_password = secrets.compare_digest(
        credentials.password.encode("utf-8"),
        expected_password.encode("utf-8"),
    )

    if not (valid_user and valid_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid dashboard credentials",
            headers={"WWW-Authenticate": "Basic"},
        )


@router.get("/", response_class=HTMLResponse)
def dashboard_home(
    request: Request,
    _: None = Depends(require_dashboard_login),
):
    try:
        report = run_live_monitor(window_minutes=5)

    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Dashboard monitoring unavailable",
        )

    monitoring = report["monitoring"]
    alerts = monitoring["alerts"]

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "page_title": "Enterprise AI Security Platform",
            "dashboard_status": "Development",
            "total_events": report["valid_events_loaded"],
            "alert_count": monitoring["alert_count"],
            "high_severity": sum(
                1 for alert in alerts
                if alert["severity"] == "high"
            ),
            "invalid_lines": report["invalid_lines"],
            "events_in_window": monitoring["events_in_window"],
            "alerts": alerts,
        },
    )



@router.get("/monitoring", response_class=HTMLResponse)
def dashboard_monitoring(
    request: Request,
    _: None = Depends(require_dashboard_login),
):
    try:
        report = run_live_monitor(window_minutes=5)
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Dashboard monitoring unavailable",
        )

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "page_title": "Security Monitoring",
            "dashboard_status": "Development",
            "active_page": "monitoring",
            "total_events": report["valid_events_loaded"],
            "alert_count": report["monitoring"]["alert_count"],
            "high_severity": sum(
                1 for alert in report["monitoring"]["alerts"]
                if alert["severity"] == "high"
            ),
            "invalid_lines": report["invalid_lines"],
            "events_in_window": report["monitoring"]["events_in_window"],
            "alerts": report["monitoring"]["alerts"],
            "window_minutes": 5,
        },
    )


@router.get("/rules", response_class=HTMLResponse)
def dashboard_rules(
    request: Request,
    _: None = Depends(require_dashboard_login),
):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "page_title": "Detection Rules",
            "dashboard_status": "Development",
            "active_page": "rules",
            "detection_rules": [
                {"rule_id": rule_id, **rule}
                for rule_id, rule in DETECTION_RULES.items()
            ],
        },
    )



@router.get("/events", response_class=HTMLResponse)
def dashboard_events(
    request: Request,
    request_id: str = Query(default="", max_length=128),
    decision: str = Query(default="all"),
    limit: int = Query(default=50, ge=1, le=100),
    _: None = Depends(require_dashboard_login),
):
    allowed_decisions = {
        "all",
        "supported_by_checks",
        "unsupported_by_checks",
        "review_required",
        "evaluation_error",
    }

    if decision not in allowed_decisions:
        raise HTTPException(
            status_code=422,
            detail="Invalid security decision filter",
        )

    try:
        audit_data = load_audit_events()
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Audit history temporarily unavailable",
        )

    events = audit_data["events"]

    if decision != "all":
        events = [
            event
            for event in events
            if event["decision"] == decision
        ]

    if request_id:
        events = [
            event
            for event in events
            if request_id.lower()
            in event["request_id"].lower()
        ]

    events = sorted(
        events,
        key=lambda event: event["timestamp"],
        reverse=True,
    )

    filtered_count = len(events)
    recent_events = events[:limit]

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "page_title": "Audit Events",
            "dashboard_status": "Development",
            "active_page": "events",
            "audit_events": recent_events,
            "total_events": audit_data["valid_events"],
            "invalid_lines": audit_data["invalid_lines"],
            "filtered_count": filtered_count,
            "selected_decision": decision,
            "search_request_id": request_id,
            "selected_limit": limit,
        },
    )

