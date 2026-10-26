
from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(
    title="Enterprise AI Security Lab",
    description="Enterprise AI engineering and security research API",
    version="0.1.0",
)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=2000)


class ChatResponse(BaseModel):
    response: str
    model: str
    status: str


@app.get("/")
def root():
    return {
        "project": "Enterprise AI Security Lab",
        "version": "0.1.0",
        "status": "development",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "api",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/chat", response_model=ChatResponse)
def chat(request: ChatRequest):
    # Placeholder until we integrate our Qwen model.
    return ChatResponse(
        response=f"Received message: {request.message}",
        model="not-connected",
        status="placeholder",
    )
