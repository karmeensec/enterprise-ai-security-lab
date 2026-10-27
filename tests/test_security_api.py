
import pytest
from fastapi.testclient import TestClient

from backend.main import app, get_security_service
from backend.security_service import SecurityAssessment


class FakeSecurityService:
    def assess_claim(
        self,
        claim,
        cited_document,
        retrieved_document_ids,
        known_document_ids,
    ):
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


PAYLOAD = {
    "claim": "Employees must use an approved VPN.",
    "cited_document": "POL-005",
    "retrieved_document_ids": ["POL-005"],
}


@pytest.fixture
def client():
    app.dependency_overrides[get_security_service] = (
        lambda: FakeSecurityService()
    )

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()


def test_security_evaluation_success(client):
    response = client.post(
        "/security/evaluate",
        json=PAYLOAD,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["decision"] == "supported_by_checks"
    assert data["review_required"] is False
    assert data["citation_validation"]["status"] == (
        "references_verified"
    )


def test_security_evaluation_request_id(client):
    response = client.post(
        "/security/evaluate",
        json=PAYLOAD,
    )

    assert response.status_code == 200
    assert response.json()["request_id"] == (
        response.headers["X-Request-ID"]
    )


def test_security_evaluation_review_required(client):
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


def test_security_evaluation_invalid_request(client):
    response = client.post(
        "/security/evaluate",
        json={
            "claim": "",
            "cited_document": "POL-005",
            "retrieved_document_ids": [],
        },
    )

    assert response.status_code == 422


def test_security_evaluation_service_failure(client):
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
