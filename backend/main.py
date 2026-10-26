
import logging
import time
import uuid
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from backend.llm_service import (
    MODEL_NAME,
    InputTooLongError,
    get_llm_service,
)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("enterprise_ai_security_lab")

app = FastAPI(
    title="Enterprise AI Security Lab",
    description="Enterprise AI security research API",
    version="0.3.0",
)


class ChatRequest(BaseModel):
    message: str = Field(
        min_length=1,
        max_length=2000
    )


class ChatResponse(BaseModel):
    response: str
    model: str
    status: str
    generation_time_seconds: float
    input_tokens: int
    generated_tokens: int
    truncated: bool
    request_id: str


@app.middleware("http")
async def request_tracking(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id

    start = time.perf_counter()

    response = await call_next(request)

    elapsed = time.perf_counter() - start

    response.headers["X-Request-ID"] = request_id

    # Log metadata only, not user prompts or model replies.
    logger.info(
        "request_id=%s method=%s path=%s status=%s duration=%.3fs",
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        elapsed,
    )

    return response


@app.get("/")
def root():
    return {
        "project": "Enterprise AI Security Lab",
        "version": "0.3.0",
        "status": "development",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "api",
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
    }


@app.post("/chat", response_model=ChatResponse)
def chat(
    request: ChatRequest,
    http_request: Request,
    llm=Depends(get_llm_service),
):
    request_id = http_request.state.request_id

    try:
        result = llm.generate(request.message)

    except InputTooLongError:
        raise HTTPException(
            status_code=413,
            detail="Input exceeds the token limit",
        )

    except Exception:
        logger.exception(
            "AI inference failed request_id=%s",
            request_id,
        )

        raise HTTPException(
            status_code=503,
            detail="AI service temporarily unavailable",
        )

    return ChatResponse(
        **result,
        request_id=request_id,
    )
