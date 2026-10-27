
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

from backend.retrieval_service import get_retrieval_service
from backend.citation_validator import validate_citations

from backend.security_service import AISecurityService
from backend.grounding_validator import load_policies


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
    claim: str = Field(min_length=1, max_length=2000)
    cited_document: str = Field(min_length=1, max_length=100)
    retrieved_document_ids: list[str] = Field(
        min_length=1,
        max_length=20,
    )


class SecurityEvaluationResponse(BaseModel):
    request_id: str
    citation_validation: dict
    grounding_validation: dict
    decision: str
    review_required: bool


def get_security_service():
    return AISecurityService()



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



@app.post("/chat/rag", response_model=RAGChatResponse)
def rag_chat(
    request: ChatRequest,
    http_request: Request,
    llm=Depends(get_llm_service),
    retriever=Depends(get_retrieval_service),
):
    request_id = http_request.state.request_id

    try:
        documents = retriever.search(
            request.message,
            top_k=3
        )

        if not documents:
            raise HTTPException(
                status_code=404,
                detail="No relevant documents available"
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
            context=context
        )

    except HTTPException:
        raise

    except InputTooLongError:
        raise HTTPException(
            status_code=413,
            detail="RAG input exceeds token limit"
        )

    except Exception:
        logger.exception(
            "RAG request failed request_id=%s",
            request_id
        )

        raise HTTPException(
            status_code=503,
            detail="RAG service temporarily unavailable"
        )

    sources = [
        SourceDocument(
            document_id=doc["document_id"],
            title=doc["title"],
            similarity_score=doc["similarity_score"]
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

    citation_result = validate_citations(
        answer=result["response"],
        retrieved_document_ids=retrieved_ids,
        known_document_ids=known_ids,
    )


    return RAGChatResponse(
        **result,
        request_id=request_id,
        sources=sources,
        retrieval_count=len(sources),
        citation_validation=CitationValidation(**citation_result),
    )



@app.post(
    "/security/evaluate",
    response_model=SecurityEvaluationResponse,
)
def evaluate_security(
    request: SecurityEvaluationRequest,
    http_request: Request,
    service: AISecurityService = Depends(get_security_service),
):
    request_id = http_request.state.request_id

    try:
        policies = load_policies()

        assessment = service.assess_claim(
            claim=request.claim,
            cited_document=request.cited_document,
            retrieved_document_ids=request.retrieved_document_ids,
            known_document_ids=list(policies.keys()),
        )

        return SecurityEvaluationResponse(
            request_id=request_id,
            **assessment.to_dict(),
        )

    except Exception:
        logger.exception(
            "Security evaluation failed request_id=%s",
            request_id,
        )

        raise HTTPException(
            status_code=503,
            detail="Security evaluation temporarily unavailable",
        )
