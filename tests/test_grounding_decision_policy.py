
import pytest

from backend.grounding_decision_policy import (
    decide_grounding_action,
)


@pytest.mark.parametrize(
    "rule_status,hybrid_status,expected_action",
    [
        ("supported", "supported", "release_candidate"),
        ("supported", "needs_review", "review_required"),
        ("needs_review", "needs_review", "review_required"),
        ("unsupported", "needs_review", "block"),
        ("unsupported", "unsupported", "block"),
        ("unknown_source", "unknown_source", "block"),
        ("needs_review", "unsupported", "block"),
    ],
)
def test_grounding_decisions(
    rule_status,
    hybrid_status,
    expected_action,
):
    result = decide_grounding_action(
        rule_status=rule_status,
        hybrid_status=hybrid_status,
        citations_verified=True,
    )

    assert result["action"] == expected_action


def test_invalid_citation_blocks_candidate():
    result = decide_grounding_action(
        rule_status="supported",
        hybrid_status="supported",
        citations_verified=False,
    )

    assert result["action"] == "block"


def test_injected_context_blocks_candidate():
    result = decide_grounding_action(
        rule_status="supported",
        hybrid_status="supported",
        citations_verified=True,
        injection_detected=True,
    )

    assert result["action"] == "block"
