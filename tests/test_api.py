
import uuid

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.llm_service import (
    InputTooLongError,
    get_llm_service,
)


class FakeLLMService:
    def generate(self, message):
        return {
            "response": f"Mock answer to: {message}",
            "model": "mock-model",
            "status": "success",
            "generation_time_seconds": 0.001,
            "input_tokens": 20,
            "generated_tokens": 10,
            "truncated": False,
        }


@pytest.fixture
def client():
    app.dependency_overrides[get_llm_service] = (
        lambda: FakeLLMService()
    )

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()


def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["project"] == (
        "Enterprise AI Security Lab"
    )


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_chat_endpoint(client):
    response = client.post(
        "/chat",
        json={"message": "What is prompt injection?"},
    )

    data = response.json()

    assert response.status_code == 200
    assert data["model"] == "mock-model"
    assert data["status"] == "success"
    assert data["truncated"] is False
    assert data["generated_tokens"] == 10


def test_empty_message_rejected(client):
    response = client.post(
        "/chat", json={"message": ""}
    )
    assert response.status_code == 422


def test_oversized_message_rejected(client):
    response = client.post(
        "/chat", json={"message": "A" * 2001}
    )
    assert response.status_code == 422


def test_missing_message_rejected(client):
    response = client.post("/chat", json={})
    assert response.status_code == 422


def test_invalid_message_type_rejected(client):
    response = client.post(
        "/chat", json={"message": 12345}
    )
    assert response.status_code == 422


def test_request_id_header(client):
    response = client.get("/health")

    request_id = response.headers["X-Request-ID"]
    assert str(uuid.UUID(request_id)) == request_id


def test_chat_request_id_matches_header(client):
    response = client.post(
        "/chat", json={"message": "Test"}
    )

    assert response.status_code == 200
    assert response.json()["request_id"] == (
        response.headers["X-Request-ID"]
    )


def test_model_inference_error_returns_503(client):
    class BrokenLLM:
        def generate(self, message):
            raise RuntimeError("Internal model failure")

    app.dependency_overrides[get_llm_service] = (
        lambda: BrokenLLM()
    )

    response = client.post(
        "/chat", json={"message": "Hello"}
    )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "AI service temporarily unavailable"
    )
    assert "Internal model failure" not in response.text


def test_token_limit_returns_413(client):
    class LimitedLLM:
        def generate(self, message):
            raise InputTooLongError("Too many tokens")

    app.dependency_overrides[get_llm_service] = (
        lambda: LimitedLLM()
    )

    response = client.post(
        "/chat", json={"message": "Test"}
    )

    assert response.status_code == 413


def test_incomplete_generation_metadata(client):
    class TruncatedLLM:
        def generate(self, message):
            result = FakeLLMService().generate(message)
            result["truncated"] = True
            result["status"] = "incomplete"
            return result

    app.dependency_overrides[get_llm_service] = (
        lambda: TruncatedLLM()
    )

    response = client.post(
        "/chat", json={"message": "Test"}
    )

    assert response.status_code == 200
    assert response.json()["truncated"] is True
    assert response.json()["status"] == "incomplete"
