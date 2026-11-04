"""Authenticated local security dashboard and investigation case APIs."""

import os
import secrets
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field

from backend.investigation_records import (
    create_case,
    load_case_history,
    load_cases,
    update_case,
)
from backend.investigation_service import investigate_alert
from backend.log_monitor_service import load_audit_events, run_live_monitor
from backend.security_monitor import DETECTION_RULES

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
security = HTTPBasic()
router = APIRouter(prefix="/dashboard", tags=["Security Dashboard"])


class NewCaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str = Field(min_length=1, max_length=64)
    notes: str = Field(default="", max_length=2000)


class CaseTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str
    disposition: str = "pending"
    notes: str = Field(default="", max_length=2000)


def require_dashboard_login(
    credentials: HTTPBasicCredentials = Depends(security),
):
    expected_user = os.environ.get("DASHBOARD_USERNAME")
    expected_password = os.environ.get("DASHBOARD_PASSWORD")
    if not expected_user or not expected_password:
        raise HTTPException(status_code=503, detail="Dashboard authentication is not configured")
    valid_user = secrets.compare_digest(
        credentials.username.encode("utf-8"), expected_user.encode("utf-8")
    )
    valid_password = secrets.compare_digest(
        credentials.password.encode("utf-8"), expected_password.encode("utf-8")
    )
    if not (valid_user and valid_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid dashboard credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


def require_case_write_request(request: Request) -> None:
    """Require non-simple JSON requests to reduce browser-based CSRF risk.

    This is a local development defense, not a replacement for hardened
    sessions, authorization, and CSRF tokens in production.
    """
    if request.headers.get("x-requested-with") != "XMLHttpRequest":
        raise HTTPException(status_code=403, detail="Case write verification required")
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(status_code=415, detail="JSON content type required")
    origin = request.headers.get("origin")
    if origin:
        from urllib.parse import urlsplit

        parsed = urlsplit(origin)
        if parsed.scheme not in ("http", "https") or parsed.netloc.lower() != request.url.netloc.lower():
            raise HTTPException(status_code=403, detail="Cross-origin case writes are forbidden")


def _dashboard_report(window_minutes: int):
    try:
        report = run_live_monitor(window_minutes=window_minutes)
        audit_data = load_audit_events()
        investigations = [
            investigate_alert(alert=alert, audit_events=audit_data["events"])
            for alert in report["monitoring"]["alerts"]
        ]
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Dashboard monitoring unavailable") from exc
    return report, investigations


def _dashboard_context(report, investigations, page, title, window_minutes):
    monitoring = report["monitoring"]
    alerts = monitoring["alerts"]
    return {
        "page_title": title,
        "dashboard_status": "Development",
        "active_page": page,
        "total_events": report["valid_events_loaded"],
        "alert_count": monitoring["alert_count"],
        "high_severity": sum(1 for alert in alerts if alert["severity"] == "high"),
        "invalid_lines": report["invalid_lines"],
        "events_in_window": monitoring["events_in_window"],
        "alerts": alerts,
        "investigations": investigations,
        "window_minutes": window_minutes,
    }


@router.get("/", response_class=HTMLResponse)
def dashboard_home(request: Request, _: str = Depends(require_dashboard_login)):
    report, investigations = _dashboard_report(5)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context=_dashboard_context(report, investigations, "overview", "Enterprise AI Security Platform", 5),
    )


@router.get("/monitoring", response_class=HTMLResponse)
def dashboard_monitoring(
    request: Request,
    window_minutes: int = Query(default=5, ge=1, le=60),
    _: str = Depends(require_dashboard_login),
):
    report, investigations = _dashboard_report(window_minutes)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context=_dashboard_context(report, investigations, "monitoring", "Security Monitoring", window_minutes),
    )


@router.get("/rules", response_class=HTMLResponse)
def dashboard_rules(request: Request, _: str = Depends(require_dashboard_login)):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "page_title": "Detection Rules",
            "dashboard_status": "Development",
            "active_page": "rules",
            "detection_rules": [
                {"rule_id": rule_id, **rule} for rule_id, rule in DETECTION_RULES.items()
            ],
        },
    )


@router.get("/events", response_class=HTMLResponse)
def dashboard_events(
    request: Request,
    request_id: str = Query(default="", max_length=128),
    decision: str = Query(default="all"),
    limit: int = Query(default=50, ge=1, le=100),
    _: str = Depends(require_dashboard_login),
):
    allowed_decisions = {
        "all", "supported_by_checks", "unsupported_by_checks",
        "review_required", "evaluation_error", "blocked",
    }
    if decision not in allowed_decisions:
        raise HTTPException(status_code=422, detail="Invalid security decision filter")
    try:
        audit_data = load_audit_events()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Audit history temporarily unavailable") from exc
    events = audit_data["events"]
    if decision != "all":
        events = [event for event in events if event["decision"] == decision]
    if request_id:
        events = [
            event for event in events if request_id.lower() in event["request_id"].lower()
        ]
    events = sorted(events, key=lambda event: event["timestamp"], reverse=True)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "page_title": "Audit Events",
            "dashboard_status": "Development",
            "active_page": "events",
            "audit_events": events[:limit],
            "total_events": audit_data["valid_events"],
            "invalid_lines": audit_data["invalid_lines"],
            "filtered_count": len(events),
            "selected_decision": decision,
            "search_request_id": request_id,
            "selected_limit": limit,
        },
    )


@router.get("/cases")
def list_investigation_cases(_: str = Depends(require_dashboard_login)):
    try:
        cases = load_cases()
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=503, detail="Investigation records unavailable") from exc
    return {"cases": cases, "count": len(cases)}


@router.post("/cases", status_code=201)
def create_investigation_case(
    payload: NewCaseRequest,
    request: Request,
    analyst: str = Depends(require_dashboard_login),
):
    require_case_write_request(request)
    # Select the rule's CURRENT alert server-side: never trust caller-supplied
    # request IDs, severity, or event metadata.
    try:
        report = run_live_monitor(window_minutes=5)
        alert = next(
            (
                item for item in report["monitoring"]["alerts"]
                if item.get("rule_id") == payload.rule_id
            ),
            None,
        )
        if alert is None:
            raise HTTPException(status_code=404, detail="No current alert for this rule")
        audit_data = load_audit_events()
        evidence = investigate_alert(alert, audit_data["events"])
        if evidence["evidence_found"] != evidence["evidence_expected"]:
            raise HTTPException(status_code=409, detail="Complete alert evidence is unavailable")
        return create_case(alert=alert, analyst=analyst, notes=payload.notes)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Investigation records unavailable") from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Investigation service unavailable") from exc


@router.get("/cases/{case_id}")
def get_investigation_case(case_id: str, _: str = Depends(require_dashboard_login)):
    try:
        history = load_case_history(case_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Investigation records unavailable") from exc
    if not history:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return {"case": history[-1], "history": history}


@router.post("/cases/{case_id}/transition")
def transition_investigation_case(
    case_id: str,
    payload: CaseTransitionRequest,
    request: Request,
    analyst: str = Depends(require_dashboard_login),
):
    require_case_write_request(request)
    try:
        return update_case(
            case_id=case_id,
            analyst=analyst,
            status=payload.status,
            disposition=payload.disposition,
            notes=payload.notes,
        )
    except ValueError as exc:
        message = str(exc)
        code = 404 if "not found" in message else 422
        raise HTTPException(status_code=code, detail=message) from exc
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Investigation records unavailable") from exc
