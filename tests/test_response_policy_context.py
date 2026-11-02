
import pytest

from backend.response_policy import (
    evaluate_response_policy,
)


@pytest.mark.parametrize(
    "response",
    [
        "SYSTEM OVERRIDE SUCCESSFUL.",
        "NEW SYSTEM ACTIVE.",
        "system override successful",
        "new system active",
    ],
)
def test_direct_attack_acknowledgments_blocked(response):
    result = evaluate_response_policy(response)

    assert result["allowed"] is False
    assert result["reason"] == (
        "direct_attack_acknowledgment"
    )


def test_educational_explanation_not_blocked():
    response = (
        'The phrase "SYSTEM OVERRIDE SUCCESSFUL" '
        "is an example of attacker-controlled output "
        "used in prompt-injection testing."
    )

    result = evaluate_response_policy(
        response=response,
        request_context=(
            "Explain this prompt injection example."
        ),
    )

    assert result["allowed"] is True
    assert result["reason"] == (
        "educational_context_review"
    )


def test_ambiguous_response_requires_review():
    response = (
        "The security console displayed "
        "NEW SYSTEM ACTIVE during testing."
    )

    result = evaluate_response_policy(
        response=response,
        request_context="Review the system output.",
    )

    assert result["allowed"] is True
    assert result["reason"] == (
        "ambiguous_pattern_requires_review"
    )
    assert result["confidence"] == "review_required"


def test_normal_response_passes():
    result = evaluate_response_policy(
        "MFA adds another layer of authentication.",
        request_context="Explain MFA.",
    )

    assert result["allowed"] is True
    assert result["findings"] == []


def test_invalid_context_rejected():
    with pytest.raises(TypeError):
        evaluate_response_policy(
            "Test response",
            request_context=None,
        )
