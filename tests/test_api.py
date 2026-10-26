
from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["project"] == "Enterprise AI Security Lab"


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["service"] == "api"


def test_chat_endpoint():
    response = client.post(
        "/chat",
        json={"message": "What is prompt injection?"}
    )

    assert response.status_code == 200
    assert response.json()["status"] == "placeholder"
    assert response.json()["model"] == "not-connected"


def test_empty_message_rejected():
    response = client.post(
        "/chat",
        json={"message": ""}
    )

    assert response.status_code == 422


def test_oversized_message_rejected():
    response = client.post(
        "/chat",
        json={"message": "A" * 2001}
    )

    assert response.status_code == 422


def test_missing_message_rejected():
    response = client.post(
        "/chat",
        json={}
    )

    assert response.status_code == 422


def test_invalid_message_type_rejected():
    response = client.post(
        "/chat",
        json={"message": 12345}
    )

    assert response.status_code == 422
