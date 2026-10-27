
from backend.security_service import AISecurityService


KNOWN = ["POL-001", "POL-002", "POL-005"]
RETRIEVED = ["POL-002", "POL-005"]


def make_service(status):
    def fake_grounding_checker(claim, cited_document):
        return {
            "status": status,
            "cited_document": cited_document,
            "reason": "Simulated result",
        }

    return AISecurityService(
        grounding_checker=fake_grounding_checker
    )


def assess(service, cited_document="POL-002"):
    return service.assess_claim(
        claim="Corporate passwords require at least 14 characters.",
        cited_document=cited_document,
        retrieved_document_ids=RETRIEVED,
        known_document_ids=KNOWN,
    )


def test_supported_claim():
    result = assess(make_service("supported"))

    assert result.decision == "supported_by_checks"
    assert result.review_required is False
    assert result.citation_validation[
        "all_references_verified"
    ] is True


def test_unsupported_claim():
    result = assess(make_service("unsupported"))

    assert result.decision == "unsupported_by_checks"
    assert result.review_required is True


def test_uncertain_claim():
    result = assess(make_service("needs_review"))

    assert result.decision == "review_required"
    assert result.review_required is True


def test_unretrieved_citation():
    result = assess(
        make_service("supported"),
        cited_document="POL-001",
    )

    assert result.decision == "review_required"
    assert result.review_required is True
    assert result.grounding_validation[
        "status"
    ] == "not_evaluated"


def test_unknown_citation():
    result = assess(
        make_service("supported"),
        cited_document="POL-999",
    )

    assert result.decision == "review_required"
    assert result.citation_validation[
        "unknown_citations"
    ] == ["POL-999"]


def test_structured_response():
    result = assess(make_service("supported"))

    data = result.to_dict()

    assert "citation_validation" in data
    assert "grounding_validation" in data
    assert "decision" in data
    assert "review_required" in data
