
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.llm_service import get_llm_service
from backend.output_guardrail import SAFE_FALLBACK


class FakeLLM:
    def __init__(self, response):
        self.response = response

    def generate(self, message):
        return {
            "response": self.response,
            "model": "mock-qwen",
            "status": "success",
            "generation_time_seconds": 0.02,
            "input_tokens": 50,
            "generated_tokens": 25,
            "truncated": False,
        }


@pytest.fixture
def mock_chat():
    original_overrides = app.dependency_overrides.copy()

    def configure(response):
        app.dependency_overrides[get_llm_service] = (
            lambda: FakeLLM(response)
        )

    try:
        with TestClient(app) as client:
            yield client, configure
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original_overrides)


def test_normal_response_is_preserved(mock_chat):
    client, configure = mock_chat

    configure(
        "MFA requires multiple authentication factors."
    )

    response = client.post(
        "/chat",
        json={"message": "What is MFA?"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "success"
    assert data["response"] == (
        "MFA requires multiple authentication factors."
    )


def test_unsupported_citation_is_blocked(mock_chat):
    client, configure = mock_chat

    configure(
        "MFA requires multiple factors. [POL-001]"
    )

    response = client.post(
        "/chat",
        json={"message": "What is MFA?"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "guardrail_blocked"
    assert data["response"] == SAFE_FALLBACK
    assert "[POL-001]" not in data["response"]


def test_fabricated_policy_is_blocked(mock_chat):
    client, configure = mock_chat

    configure(
        "Company policy POL-999 requires employees "
        "to share passwords with managers."
    )

    response = client.post(
        "/chat",
        json={"message": "Explain company policy."},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "guardrail_blocked"
    assert data["response"] == SAFE_FALLBACK
    assert "POL-999" not in data["response"]


def test_block_preserves_response_metadata(mock_chat):
    client, configure = mock_chat

    configure("Follow [POL-999].")

    response = client.post(
        "/chat",
        json={"message": "Test policy."},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["model"] == "mock-qwen"
    assert data["input_tokens"] == 50
    assert data["generated_tokens"] == 25
    assert data["generation_time_seconds"] == 0.02
    assert data["truncated"] is False

    assert data["request_id"] == (
        response.headers["X-Request-ID"]
    )


def test_uncited_claim_limitation_is_documented(mock_chat):
    client, configure = mock_chat

    configure(
        "Company policy requires everyone "
        "to share their passwords."
    )

    response = client.post(
        "/chat",
        json={"message": "Explain company policy."},
    )

    assert response.status_code == 200

    # Known limitation: no recognizable policy ID.
    assert response.json()["status"] == "success"
