
"""
Experiment 57 — Integrated FastAPI Entry Point.

Includes the existing Enterprise AI Security Lab
application and the authenticated AI Agent API.
"""

from backend.main import app
from backend.agent_api import router as agent_router


app.include_router(agent_router)
