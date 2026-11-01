
from fastapi.testclient import TestClient

from backend.main import app


def test_client_supplied_retrieval_ids_are_rejected():
    """
    Regression test for the Experiment 38
    retrieval trust-boundary vulnerability.

    Clients must not be able to declare
    which documents the server retrieved.
    """
    with TestClient(app) as client:
        response = client.post(
            "/security/evaluate",
            json={
                "claim": "Synthetic test claim",
                "cited_document": "POL-005",
                "retrieved_document_ids": ["POL-005"],
            },
        )

    assert response.status_code == 422

    details = response.json()["detail"]

    assert any(
        error.get("type") == "extra_forbidden"
        and "retrieved_document_ids" in error.get("loc", [])
        for error in details
    )
