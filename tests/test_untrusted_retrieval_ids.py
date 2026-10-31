
from fastapi.testclient import TestClient

from backend.main import app
from backend.main import get_security_service


client = TestClient(app)


class FakeSecurityService:
    def assess_claim(
        self,
        claim,
        cited_document,
        retrieved_document_ids,
        known_document_ids,
    ):
        from backend.citation_validator import validate_citations
        from backend.security_service import SecurityAssessment

        citation = validate_citations(
            answer=f"[{cited_document}]",
            retrieved_document_ids=retrieved_document_ids,
            known_document_ids=known_document_ids,
        )

        return SecurityAssessment(
            citation_validation=citation,
            grounding_validation={
                "status": "not_evaluated",
                "reason": "Isolated citation trust test",
            },
            decision="review_required",
            review_required=True,
        )


def test_client_supplied_retrieval_ids_pass_citation_check():
    app.dependency_overrides[get_security_service] = (
        lambda: FakeSecurityService()
    )

    try:
        response = client.post(
            "/security/evaluate",
            json={
                "claim": "Synthetic test claim",
                "cited_document": "POL-005",
                "retrieved_document_ids": ["POL-005"],
            },
        )

        assert response.status_code == 200

        data = response.json()

        assert (
            data["citation_validation"]["status"]
            == "references_verified"
        )

        assert (
            data["citation_validation"]["all_references_verified"]
            is True
        )

        # Citation verification did not establish
        # that actual retrieval occurred.
        assert (
            data["citation_validation"]["claim_support_verified"]
            is False
        )

    finally:
        app.dependency_overrides.clear()
