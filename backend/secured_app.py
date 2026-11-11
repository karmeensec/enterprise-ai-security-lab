
"""
Enterprise AI Security Platform.

Local Docker:
    Full authenticated application with Qwen and agent tools.

Render demo:
    Public, read-only portfolio dashboard.
    No model loading, live telemetry, or response actions.
"""

import os


if os.environ.get("RENDER_DEMO") == "1":
    from datetime import datetime, timezone
    from pathlib import Path

    from fastapi import (
        FastAPI,
        HTTPException,
        Query,
        Request,
    )
    from fastapi.responses import (
        HTMLResponse,
        RedirectResponse,
    )
    from fastapi.templating import Jinja2Templates

    app = FastAPI(
        title="Enterprise AI Security Lab — Portfolio Demo",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    templates = Jinja2Templates(
        directory=str(
            Path(__file__).resolve().parent.parent
            / "dashboard"
            / "templates"
        )
    )

    BANNER = (
        '<div role="status" style="'
        'padding:14px 24px;'
        'background:#fff2d6;'
        'color:#684c13;'
        'font:600 13px Segoe UI,Arial,sans-serif">'
        'PORTFOLIO DEMO · Public read-only view · '
        'No live telemetry · AI inference disabled'
        '</div>'
    )

    @app.middleware("http")
    async def security_headers(
        request: Request,
        call_next,
    ):
        response = await call_next(request)

        response.headers["Cache-Control"] = "no-store"
        response.headers[
            "X-Content-Type-Options"
        ] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers[
            "Referrer-Policy"
        ] = "no-referrer"

        return response

    def render_page(
        request: Request,
        template_name: str,
        context: dict,
    ):
        response = templates.TemplateResponse(
            request=request,
            name=template_name,
            context=context,
        )

        html = response.body.decode("utf-8")

        html = html.replace(
            "<body>",
            "<body>\n" + BANNER,
            1,
        )

        return HTMLResponse(html)

    def dashboard_context(
        page: str,
        title: str,
        window: int = 5,
    ) -> dict:
        return {
            "page_title": title,
            "dashboard_status": "Portfolio demo",
            "active_page": page,
            "total_events": 0,
            "alert_count": 0,
            "high_severity": 0,
            "invalid_lines": 0,
            "events_in_window": 0,
            "alerts": [],
            "investigations": [],
            "window_minutes": window,
        }

    @app.get("/health")
    def health():
        return {
            "status": "healthy",
            "mode": "portfolio_demo",
            "ai_inference": False,
            "read_only": True,
        }

    @app.get("/")
    def home():
        return RedirectResponse(
            "/dashboard/",
            status_code=307,
        )

    @app.get(
        "/dashboard/",
        response_class=HTMLResponse,
    )
    def overview(request: Request):
        return render_page(
            request,
            "index.html",
            dashboard_context(
                "overview",
                "Security Overview",
            ),
        )

    @app.get(
        "/dashboard/monitoring",
        response_class=HTMLResponse,
    )
    def monitoring(
        request: Request,
        window_minutes: int = Query(
            default=5,
            ge=1,
            le=60,
        ),
    ):
        return render_page(
            request,
            "index.html",
            dashboard_context(
                "monitoring",
                "Security Monitoring",
                window_minutes,
            ),
        )

    @app.get(
        "/dashboard/rules",
        response_class=HTMLResponse,
    )
    def rules(request: Request):
        context = dashboard_context(
            "rules",
            "Detection Rules",
        )

        context["detection_rules"] = []

        return render_page(
            request,
            "index.html",
            context,
        )

    @app.get(
        "/dashboard/events",
        response_class=HTMLResponse,
    )
    def events(
        request: Request,
        request_id: str = Query(
            default="",
            max_length=128,
        ),
        decision: str = "all",
        limit: int = Query(
            default=50,
            ge=1,
            le=100,
        ),
    ):
        allowed_decisions = {
            "all",
            "supported_by_checks",
            "unsupported_by_checks",
            "review_required",
            "evaluation_error",
            "blocked",
        }

        if decision not in allowed_decisions:
            raise HTTPException(
                status_code=422,
                detail="Invalid decision filter",
            )

        context = dashboard_context(
            "events",
            "Audit Events",
        )

        context.update({
            "audit_events": [],
            "filtered_count": 0,
            "selected_decision": decision,
            "search_request_id": request_id,
            "selected_limit": limit,
        })

        return render_page(
            request,
            "index.html",
            context,
        )

    @app.get(
        "/dashboard/agent-security",
        response_class=HTMLResponse,
    )
    def agent_security(request: Request):
        return render_page(
            request,
            "agent_security.html",
            {
                "page_title": "Agent Security Monitoring",
                "monitoring_window": 5,
                "monitoring_mode": "disabled",
                "total_agent_events": 0,
                "recent_agent_events": 0,
                "invalid_agent_lines": 0,
                "alert_count": 0,
                "high_severity_count": 0,
                "alerts": [],
                "events": [],
                "display_limit": 50,
                "generated_at": datetime.now(
                    timezone.utc
                ).isoformat(),
            },
        )

    # Read-only dashboard API responses.
    # No private records are loaded.

    @app.get("/dashboard/cases")
    def list_cases():
        return {
            "cases": [],
            "count": 0,
            "mode": "read_only_demo",
        }

    @app.get("/dashboard/response-actions")
    def response_actions():
        return {
            "actions": [],
            "execution_mode": "disabled",
        }

    @app.get("/dashboard/response-plans")
    def list_plans():
        return {
            "plans": [],
            "count": 0,
            "mode": "read_only_demo",
        }

    @app.get("/dashboard/simulations")
    def list_simulations():
        return {
            "simulations": [],
            "count": 0,
            "execution_mode": "disabled",
        }

    # Block every dashboard modification.

    @app.api_route(
        "/dashboard/{path:path}",
        methods=[
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        ],
    )
    def block_dashboard_writes(path: str):
        raise HTTPException(
            status_code=403,
            detail="Portfolio demo is read-only",
        )

    # No AI agent access in the public demo.

    @app.api_route(
        "/agent/{path:path}",
        methods=[
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        ],
    )
    def block_agent(path: str):
        raise HTTPException(
            status_code=503,
            detail="AI agent unavailable in demo",
        )

    @app.api_route(
        "/chat/{path:path}",
        methods=[
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        ],
    )
    def block_chat(path: str):
        raise HTTPException(
            status_code=503,
            detail="AI inference unavailable in demo",
        )

    @app.api_route(
        "/security/{path:path}",
        methods=[
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        ],
    )
    def block_security_evaluation(path: str):
        raise HTTPException(
            status_code=503,
            detail="Security evaluation unavailable in demo",
        )

else:
    # The original full application remains protected.
    from backend.main import app

    from backend.agent_api import (
        router as agent_router,
    )

    from backend.agent_dashboard import (
        router as agent_dashboard_router,
    )

    app.include_router(agent_router)
    app.include_router(agent_dashboard_router)
