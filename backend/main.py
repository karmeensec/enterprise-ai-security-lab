
from datetime import datetime, timezone

from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

from backend.llm_service import get_llm_service, MODEL_NAME


app = FastAPI(
    title="Enterprise AI Security Lab",
    description="Enterprise AI engineering and security research API",
    version="0.2.0",
)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=2000)


class ChatResponse(BaseModel):
    response: str
    model: str
    status: str
    generation_time_seconds: float


@app.get("/")
def root():
    return {
        "project": "Enterprise AI Security Lab",
        "version": "0.2.0",
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
def chat(
    request: ChatRequest,
    llm=Depends(get_llm_service),
):
    result = llm.generate(request.message)
    return ChatResponse(**result)
