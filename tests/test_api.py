
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.llm_service import get_llm_service


class FakeLLMService:
    def generate(self, message):
        return {
            "response": f"Mock answer to: {message}",
            "model": "mock-model",
            "status": "success",
            "generation_time_seconds": 0.001,
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
    assert response.json()["project"] == "Enterprise AI Security Lab"


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_chat_endpoint(client):
    response = client.post(
        "/chat",
        json={"message": "What is prompt injection?"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert response.json()["model"] == "mock-model"
    assert "Mock answer" in response.json()["response"]
    assert "generation_time_seconds" in response.json()


def test_empty_message_rejected(client):
    response = client.post("/chat", json={"message": ""})
    assert response.status_code == 422


def test_oversized_message_rejected(client):
    response = client.post(
        "/chat",
        json={"message": "A" * 2001},
    )
    assert response.status_code == 422


def test_missing_message_rejected(client):
    response = client.post("/chat", json={})
    assert response.status_code == 422


def test_invalid_message_type_rejected(client):
    response = client.post(
        "/chat",
        json={"message": 12345},
    )
    assert response.status_code == 422
