
import pytest
from fastapi.testclient import TestClient

from backend.main import (
    app,
    get_retrieval_service,
    get_security_service,
)
from backend.security_service import SecurityAssessment


PAYLOAD = {
    "claim": "Employees must use an approved VPN.",
    "cited_document": "POL-005",
}


class FakeRetriever:
    def __init__(self):
        self.calls = []

    def search(self, question, top_k=3):
        self.calls.append((question, top_k))

        return [
            {
                "document_id": "POL-005",
                "title": "Synthetic VPN Policy",
                "content": "Employees must use an approved VPN.",
                "similarity_score": 0.95,
            }
        ]


class FakeSecurityService:
    def __init__(self):
        self.calls = []

    def assess_claim(
        self,
        claim,
        cited_document,
        retrieved_document_ids,
        known_document_ids,
    ):
        self.calls.append({
            "claim": claim,
            "cited_document": cited_document,
            "retrieved_document_ids": list(
                retrieved_document_ids
            ),
        })

        return SecurityAssessment(
            citation_validation={
                "status": "references_verified",
                "citations": [cited_document],
                "all_references_verified": True,
            },
            grounding_validation={
                "status": "supported",
                "cited_document": cited_document,
            },
            decision="supported_by_checks",
            review_required=False,
        )


class FakeReviewService(FakeSecurityService):
    def assess_claim(self, **kwargs):
        result = super().assess_claim(**kwargs)
        result.decision = "review_required"
        result.review_required = True
        result.grounding_validation["status"] = "needs_review"
        return result


class FailingSecurityService:
    def assess_claim(self, **kwargs):
        raise RuntimeError("Simulated service failure")


@pytest.fixture
def setup_client():
    retriever = FakeRetriever()
    service = FakeSecurityService()

    original_overrides = app.dependency_overrides.copy()

    app.dependency_overrides[get_retrieval_service] = (
        lambda: retriever
    )
    app.dependency_overrides[get_security_service] = (
        lambda: service
    )

    try:
        with TestClient(app) as client:
            yield client, retriever, service
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original_overrides)


def test_security_evaluation_success(setup_client):
    client, retriever, service = setup_client

    response = client.post(
        "/security/evaluate",
        json=PAYLOAD,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["decision"] == "supported_by_checks"
    assert data["review_required"] is False
    assert (
        data["citation_validation"]["status"]
        == "references_verified"
    )

    assert retriever.calls == [
        (PAYLOAD["claim"], 3)
    ]

    assert service.calls[0][
        "retrieved_document_ids"
    ] == ["POL-005"]


def test_security_evaluation_request_id(setup_client):
    client, _, _ = setup_client

    response = client.post(
        "/security/evaluate",
        json=PAYLOAD,
    )

    assert response.status_code == 200
    assert response.json()["request_id"] == (
        response.headers["X-Request-ID"]
    )


def test_security_evaluation_review_required(setup_client):
    client, _, _ = setup_client

    app.dependency_overrides[get_security_service] = (
        lambda: FakeReviewService()
    )

    response = client.post(
        "/security/evaluate",
        json=PAYLOAD,
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "review_required"
    assert response.json()["review_required"] is True


def test_security_evaluation_invalid_request(setup_client):
    client, _, _ = setup_client

    response = client.post(
        "/security/evaluate",
        json={
            "claim": "",
            "cited_document": "POL-005",
        },
    )

    assert response.status_code == 422


def test_security_evaluation_service_failure(setup_client):
    client, _, _ = setup_client

    app.dependency_overrides[get_security_service] = (
        lambda: FailingSecurityService()
    )

    response = client.post(
        "/security/evaluate",
        json=PAYLOAD,
    )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "Security evaluation temporarily unavailable"
    )
