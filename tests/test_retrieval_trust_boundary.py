
import pytest
from fastapi.testclient import TestClient

from backend.main import (
    app,
    get_retrieval_service,
    get_security_service,
)
from backend.security_service import SecurityAssessment


class TrackingRetriever:
    def __init__(self, documents):
        self.documents = documents
        self.calls = []

    def search(self, question, top_k=3):
        self.calls.append((question, top_k))
        return self.documents


class TrackingSecurityService:
    def __init__(self):
        self.received_ids = None

    def assess_claim(
        self,
        claim,
        cited_document,
        retrieved_document_ids,
        known_document_ids,
    ):
        self.received_ids = list(retrieved_document_ids)

        return SecurityAssessment(
            citation_validation={
                "status": "test_only",
            },
            grounding_validation={
                "status": "test_only",
            },
            decision="review_required",
            review_required=True,
        )


@pytest.fixture
def setup_client():
    retriever = TrackingRetriever([
        {
            "document_id": "POL-002",
            "title": "Test Policy",
            "content": "Synthetic test document.",
            "similarity_score": 0.8,
        },
    ])
    security_service = TrackingSecurityService()

    original = app.dependency_overrides.copy()

    app.dependency_overrides[get_retrieval_service] = (
        lambda: retriever
    )
    app.dependency_overrides[get_security_service] = (
        lambda: security_service
    )

    try:
        with TestClient(app) as client:
            yield client, retriever, security_service
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original)


def test_rejects_client_supplied_retrieval_ids(setup_client):
    client, retriever, service = setup_client

    response = client.post(
        "/security/evaluate",
        json={
            "claim": "Synthetic claim",
            "cited_document": "POL-005",
            "retrieved_document_ids": ["POL-005"],
        },
    )

    assert response.status_code == 422
    assert retriever.calls == []
    assert service.received_ids is None


def test_server_controls_retrieval_evidence(setup_client):
    client, retriever, service = setup_client

    response = client.post(
        "/security/evaluate",
        json={
            "claim": "Synthetic claim",
            "cited_document": "POL-005",
        },
    )

    assert response.status_code == 200
    assert retriever.calls == [("Synthetic claim", 3)]

    # Only POL-002 was retrieved by the server.
    # The client cannot declare POL-005 as retrieved.
    assert service.received_ids == ["POL-002"]


def test_retrieval_service_failure_is_handled(setup_client):
    client, retriever, service = setup_client

    retriever.documents = None

    response = client.post(
        "/security/evaluate",
        json={
            "claim": "Synthetic claim",
            "cited_document": "POL-005",
        },
    )

    assert response.status_code == 503
    assert service.received_ids is None
