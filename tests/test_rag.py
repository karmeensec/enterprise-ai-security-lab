
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.llm_service import get_llm_service
from backend.retrieval_service import get_retrieval_service
from backend.rag_security import SAFE_RESPONSE


class FakeRetriever:
    documents = [
        {"id": "POL-001"},
        {"id": "POL-002"},
        {"id": "POL-003"},
        {"id": "POL-004"},
        {"id": "POL-005"},
    ]

    def search(self, question, top_k=3):
        return [
            {
                "document_id": "POL-001",
                "title": "MFA Policy",
                "content": "Report unexpected MFA requests.",
                "similarity_score": 0.85,
            }
        ]


class FakeLLM:
    def generate(self, message, context=None):
        assert context is not None
        assert "POL-001" in context

        return {
            "response": (
                "Report unexpected MFA requests "
                "to the security team. [POL-001]"
            ),
            "model": "mock-model",
            "status": "success",
            "generation_time_seconds": 0.001,
            "input_tokens": 50,
            "generated_tokens": 20,
            "truncated": False,
        }


@pytest.fixture
def client():
    original = app.dependency_overrides.copy()

    app.dependency_overrides[get_llm_service] = (
        lambda: FakeLLM()
    )

    app.dependency_overrides[get_retrieval_service] = (
        lambda: FakeRetriever()
    )

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original)


def test_rag_response(client):
    response = client.post(
        "/chat/rag",
        json={"message": "What is our MFA policy?"},
    )

    assert response.status_code == 200
    data = response.json()

    # Experiment 43: no automatic release.
    assert data["status"] == "review_required"
    assert data["response"] == SAFE_RESPONSE

    assert data["retrieval_count"] == 1
    assert data["sources"][0]["document_id"] == "POL-001"

    # These fields describe the original generated
    # answer, not the fallback displayed to the user.
    validation = data["citation_validation"]

    assert validation["status"] == "references_verified"
    assert validation["citations"] == ["POL-001"]
    assert validation["valid_citations"] == ["POL-001"]
    assert validation["all_references_verified"] is True
    assert validation["claim_support_verified"] is False

    assert data["model"] == "mock-model"
    assert data["generated_tokens"] == 20


def test_rag_request_id(client):
    response = client.post(
        "/chat/rag",
        json={"message": "What is MFA?"},
    )

    assert response.status_code == 200
    assert response.json()["request_id"] == (
        response.headers["X-Request-ID"]
    )


def test_rag_empty_message(client):
    response = client.post(
        "/chat/rag",
        json={"message": ""},
    )

    assert response.status_code == 422


def test_rag_oversized_message(client):
    response = client.post(
        "/chat/rag",
        json={"message": "A" * 2001},
    )

    assert response.status_code == 422
