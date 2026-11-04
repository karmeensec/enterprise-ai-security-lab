
import uuid

import pytest
from fastapi.testclient import TestClient

import backend.main as main_module

from backend.document_integrity import (
    DocumentIntegrityError,
)
from backend.llm_service import get_llm_service
from backend.retrieval_service import get_retrieval_service


ROUTES = [
    (
        "/chat/rag",
        {"message": "What is our VPN policy?"},
    ),
    (
        "/security/evaluate",
        {
            "claim": "Employees must use the approved VPN.",
            "cited_document": "POL-005",
        },
    ),
]


class FailingRetriever:
    def search(self, question, top_k=3):
        raise DocumentIntegrityError(
            "Sensitive internal path: C:/secret/policies.json "
            "SHA-256 mismatch"
        )


class ForbiddenLLM:
    def __init__(self):
        self.calls = 0

    def generate(self, *args, **kwargs):
        self.calls += 1
        raise AssertionError(
            "LLM must never run after integrity failure"
        )


@pytest.fixture
def environment(monkeypatch):
    events = []
    llm = ForbiddenLLM()

    original_overrides = (
        main_module.app.dependency_overrides.copy()
    )

    monkeypatch.setattr(
        main_module,
        "record_document_integrity_failure",
        lambda **kwargs: events.append(kwargs),
    )

    # Prevent these tests from writing normal security
    # evaluation events to the actual project audit log.
    monkeypatch.setattr(
        main_module,
        "record_security_evaluation",
        lambda **kwargs: None,
    )

    main_module.app.dependency_overrides[
        get_llm_service
    ] = lambda: llm

    try:
        with TestClient(main_module.app) as client:
            yield client, events, llm
    finally:
        main_module.app.dependency_overrides.clear()
        main_module.app.dependency_overrides.update(
            original_overrides
        )


def assert_safe_failure(response, events, route, stage):
    assert response.status_code == 503

    body = response.json()

    if route == "/chat/rag":
        assert body["detail"] == (
            "RAG service temporarily unavailable"
        )
    else:
        assert body["detail"] == (
            "Security evaluation temporarily unavailable"
        )

    serialized = response.text.lower()

    assert "c:/secret" not in serialized
    assert "sha-256 mismatch" not in serialized
    assert "policies.json" not in serialized

    assert len(events) == 1
    assert events[0]["route"] == route
    assert events[0]["stage"] == stage

    request_id = response.headers["X-Request-ID"]

    assert str(uuid.UUID(request_id)) == request_id
    assert events[0]["request_id"] == request_id


@pytest.mark.parametrize("route,payload", ROUTES)
def test_dependency_initialization_failure(
    environment,
    route,
    payload,
):
    client, events, llm = environment

    def fail_during_initialization():
        raise DocumentIntegrityError(
            "Sensitive internal path: C:/secret/policies.json "
            "SHA-256 mismatch"
        )

    main_module.app.dependency_overrides[
        get_retrieval_service
    ] = fail_during_initialization

    response = client.post(
        route,
        json=payload,
    )

    assert_safe_failure(
        response,
        events,
        route,
        "dependency_initialization",
    )

    assert llm.calls == 0


@pytest.mark.parametrize("route,payload", ROUTES)
def test_retrieval_failure(
    environment,
    route,
    payload,
):
    client, events, llm = environment

    main_module.app.dependency_overrides[
        get_retrieval_service
    ] = lambda: FailingRetriever()

    response = client.post(
        route,
        json=payload,
    )

    assert_safe_failure(
        response,
        events,
        route,
        "retrieval",
    )

    assert llm.calls == 0


def test_audit_write_failure_still_blocks(
    environment,
    monkeypatch,
):
    client, events, llm = environment

    main_module.app.dependency_overrides[
        get_retrieval_service
    ] = lambda: FailingRetriever()

    def broken_audit_writer(**kwargs):
        raise OSError("Simulated audit disk failure")

    monkeypatch.setattr(
        main_module,
        "record_document_integrity_failure",
        broken_audit_writer,
    )

    response = client.post(
        "/chat/rag",
        json={"message": "What is our VPN policy?"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "RAG service temporarily unavailable"
    )

    assert "Simulated audit disk failure" not in response.text
    assert llm.calls == 0


def test_integrity_failure_does_not_return_model_answer(
    environment,
):
    client, events, llm = environment

    main_module.app.dependency_overrides[
        get_retrieval_service
    ] = lambda: FailingRetriever()

    response = client.post(
        "/chat/rag",
        json={"message": "Explain VPN policy."},
    )

    assert response.status_code == 503
    assert "response" not in response.json()
    assert "sources" not in response.json()
    assert llm.calls == 0
