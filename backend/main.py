
import logging
import time
import uuid
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from backend.llm_service import (
    MODEL_NAME,
    InputTooLongError,
    get_llm_service,
)

from backend.retrieval_service import get_retrieval_service
from backend.citation_validator import validate_citations

from backend.security_service import AISecurityService
from backend.grounding_validator import load_policies

from backend.audit_logger import (
    record_security_evaluation,
    record_document_integrity_failure,
)
from backend.document_integrity import DocumentIntegrityError

import os
import secrets

from fastapi import Header
from backend.log_monitor_service import run_live_monitor
from dashboard.router import router as dashboard_router
from backend.output_guardrail import validate_chat_output
from backend.rag_security import evaluate_rag_answer


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("enterprise_ai_security_lab")

app = FastAPI(
    title="Enterprise AI Security Lab",
    description="Enterprise AI security research API",
    version="0.3.0",
)

app.include_router(dashboard_router)


@app.exception_handler(DocumentIntegrityError)
async def document_integrity_exception_handler(
    request: Request,
    exc: DocumentIntegrityError,
):
    """Fail closed even when a dependency cannot initialize."""
    request_id = getattr(request.state, "request_id", "unavailable")
    route = request.url.path
    stage = getattr(
        request.state, "integrity_stage", "dependency_initialization"
    )

    # Do not send exception text, policy contents, hashes or paths to clients.
    logger.error(
        "Document integrity verification failed request_id=%s route=%s stage=%s",
        request_id,
        route,
        stage,
    )

    if route in {"/chat/rag", "/security/evaluate"}:
        try:
            record_document_integrity_failure(
                request_id=request_id,
                route=route,
                stage=stage,
            )
        except Exception:
            # Audit failures must never bypass the security block.
            logger.exception(
                "Integrity audit write failed request_id=%s",
                request_id,
            )

    detail = (
        "Security evaluation temporarily unavailable"
        if route == "/security/evaluate"
        else "RAG service temporarily unavailable"
    )
    return JSONResponse(status_code=503, content={"detail": detail})

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


class SourceDocument(BaseModel):
    document_id: str
    title: str
    similarity_score: float


class CitationValidation(BaseModel):
    status: str
    citations: list[str]
    valid_citations: list[str]
    unknown_citations: list[str]
    not_retrieved: list[str]
    citation_count: int
    all_references_verified: bool
    claim_support_verified: bool



class RAGChatResponse(ChatResponse):
    sources: list[SourceDocument]
    retrieval_count: int
    citation_validation: CitationValidation



class SecurityEvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: str = Field(
        min_length=1,
        max_length=2000,
    )

    cited_document: str = Field(
        min_length=1,
        max_length=100,
    )


class SecurityEvaluationResponse(BaseModel):
    request_id: str
    citation_validation: dict
    grounding_validation: dict
    decision: str
    review_required: bool


def get_security_service():
    return AISecurityService()


def require_monitor_api_key(
    x_monitor_api_key: str | None = Header(default=None),
):
    expected_key = os.environ.get("MONITOR_API_KEY")

    if not expected_key:
        raise HTTPException(
            status_code=503,
            detail="Monitoring authentication is not configured",
        )

    if (
        x_monitor_api_key is None
        or not secrets.compare_digest(
            x_monitor_api_key,
            expected_key,
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid monitoring credentials",
        )



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

        # Preserve the original generation metadata.
        result = result.copy()

        # Ordinary chat has no verified retrieval evidence.
        # Policy citations must therefore not be trusted.
        known_ids = list(load_policies().keys())

        guardrail = validate_chat_output(
            response=result["response"],
            retrieved_document_ids=[],
            known_document_ids=known_ids,
        )


        if not guardrail["allowed"]:
            result["response"] = guardrail["response"]
            result["status"] = "guardrail_blocked"

            logger.warning(
                "Chat output blocked request_id=%s reason=%s",
                request_id,
                guardrail["reason"],
            )

        return ChatResponse(
            **result,
            request_id=request_id,
        )

    except InputTooLongError:
        raise HTTPException(
            status_code=413,
            detail="Chat input exceeds token limit",
        )

    except Exception:
        logger.exception(
            "Chat inference failed request_id=%s",
            request_id,
        )

        raise HTTPException(
            status_code=503,
            detail="AI service temporarily unavailable",
        )





@app.post("/chat/rag", response_model=RAGChatResponse)
def rag_chat(
    request: ChatRequest,
    http_request: Request,
    llm=Depends(get_llm_service),
    retriever=Depends(get_retrieval_service),
):
    request_id = http_request.state.request_id

    try:
        http_request.state.integrity_stage = "retrieval"
        documents = retriever.search(
            request.message,
            top_k=3,
        )

        if not documents:
            raise HTTPException(
                status_code=404,
                detail="No relevant documents available",
            )

        context = "\n\n".join(
            (
                f"[{doc['document_id']}] "
                f"{doc['title']}\n"
                f"{doc['content']}"
            )
            for doc in documents
        )

        result = llm.generate(
            request.message,
            context=context,
        )

        sources = [
            SourceDocument(
                document_id=doc["document_id"],
                title=doc["title"],
                similarity_score=doc["similarity_score"],
            )
            for doc in documents
        ]

        retrieved_ids = [
            doc["document_id"]
            for doc in documents
        ]

        known_ids = [
            doc["id"]
            for doc in retriever.documents
        ]

        # Citation metadata describes the original model answer,
        # not the replacement fallback shown to the user.
        citation_result = validate_citations(
            answer=result["response"],
            retrieved_document_ids=retrieved_ids,
            known_document_ids=known_ids,
        )

        security_result = evaluate_rag_answer(
            answer=result["response"],
            retrieved_context=context,
            retrieved_document_ids=retrieved_ids,
            known_document_ids=known_ids,
        )

        decision = security_result["decision"]
        result = result.copy()

        if decision == "blocked":
            result["response"] = security_result["display_response"]
            result["status"] = "guardrail_blocked"

            logger.warning(
                "RAG response blocked request_id=%s reason=%s",
                request_id,
                security_result["reason"],
            )

        elif decision == "review_required":
            result["response"] = security_result["display_response"]
            result["status"] = "review_required"

            logger.info(
                "RAG response requires review request_id=%s",
                request_id,
            )

        else:
            # Unknown decisions must never release the answer.
            raise ValueError("Unsupported RAG security decision")

        return RAGChatResponse(
            **result,
            request_id=request_id,
            sources=sources,
            retrieval_count=len(sources),
            citation_validation=CitationValidation(**citation_result),
        )

    except HTTPException:
        raise

    except DocumentIntegrityError:
        # Allow the global exception handler to audit and sanitize the failure.
        raise

    except InputTooLongError:
        raise HTTPException(
            status_code=413,
            detail="RAG input exceeds token limit",
        )

    except Exception:
        logger.exception(
            "RAG request or security evaluation failed request_id=%s",
            request_id,
        )
        raise HTTPException(
            status_code=503,
            detail="RAG service temporarily unavailable",
        )


@app.post(
    "/security/evaluate",
    response_model=SecurityEvaluationResponse,
)
def evaluate_security(
    request: SecurityEvaluationRequest,
    http_request: Request,
    service: AISecurityService = Depends(get_security_service),
    retriever=Depends(get_retrieval_service),
):
    request_id = http_request.state.request_id
    start_time = time.perf_counter()

    decision = "evaluation_error"
    review_required = True

    try:
        # Retrieve evidence on the server.
        # Client-supplied retrieval IDs are not accepted.
        http_request.state.integrity_stage = "retrieval"
        documents = retriever.search(
            request.claim,
            top_k=3,
        )

        if not isinstance(documents, list):
            raise ValueError(
                "Retrieval service returned invalid results"
            )

        retrieved_ids = []

        for document in documents:
            if not isinstance(document, dict):
                raise ValueError(
                    "Invalid retrieved document"
                )

            document_id = document.get("document_id")

            if not isinstance(document_id, str):
                raise ValueError(
                    "Retrieved document ID is missing"
                )

            if not document_id:
                raise ValueError(
                    "Retrieved document ID is empty"
                )

            if document_id not in retrieved_ids:
                retrieved_ids.append(document_id)

        policies = load_policies()

        assessment = service.assess_claim(
            claim=request.claim,
            cited_document=request.cited_document,
            retrieved_document_ids=retrieved_ids,
            known_document_ids=list(policies.keys()),
        )

        response = SecurityEvaluationResponse(
            request_id=request_id,
            **assessment.to_dict(),
        )

        decision = response.decision
        review_required = response.review_required

        return response

    except DocumentIntegrityError:
        # The global handler logs the integrity event and returns HTTP 503.
        raise

    except Exception:
        logger.exception(
            "Security evaluation failed request_id=%s",
            request_id,
        )

        raise HTTPException(
            status_code=503,
            detail=(
                "Security evaluation temporarily unavailable"
            ),
        )

    finally:
        duration_ms = (
            time.perf_counter() - start_time
        ) * 1000

        try:
            record_security_evaluation(
                request_id=request_id,
                cited_document=request.cited_document,
                decision=decision,
                review_required=review_required,
                duration_ms=duration_ms,
            )

        except Exception:
            # Logging remains best-effort in this
            # local development environment.
            logger.exception(
                "Security audit write failed request_id=%s",
                request_id,
            )



@app.get("/security/monitor")
def get_security_monitoring(
    window_minutes: int = 5,
    _: None = Depends(require_monitor_api_key),
):
    if not 1 <= window_minutes <= 60:
        raise HTTPException(
            status_code=422,
            detail="window_minutes must be between 1 and 60",
        )

    try:
        return run_live_monitor(
            window_minutes=window_minutes,
        )

    except Exception:
        logger.exception(
            "Security monitoring request failed"
        )

        raise HTTPException(
            status_code=503,
            detail="Security monitoring temporarily unavailable",
        )
