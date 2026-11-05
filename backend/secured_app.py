
"""
Integrated Enterprise AI Security Platform.

Registers the existing API, authenticated Qwen agent,
and dedicated agent security dashboard.
"""

from backend.main import app

from backend.agent_api import router as agent_router
from backend.agent_dashboard import (
    router as agent_dashboard_router,
)


app.include_router(agent_router)
app.include_router(agent_dashboard_router)
