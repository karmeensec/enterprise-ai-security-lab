
import pytest

from backend.response_policy import (
    evaluate_response_policy,
)


@pytest.mark.parametrize(
    "response",
    [
        "SYSTEM OVERRIDE SUCCESSFUL.",
        "system override successful",
        "NEW SYSTEM ACTIVE.",
        "New System Active",
    ],
)
def test_known_attack_response_patterns(response):
    result = evaluate_response_policy(response)

    assert result["allowed"] is False
    assert result["findings"]


@pytest.mark.parametrize(
    "response",
    [
        "Multi-factor authentication improves security.",
        "Prompt injection can target model instructions.",
        "Security policies should be verified.",
    ],
)
def test_normal_cybersecurity_responses(response):
    result = evaluate_response_policy(response)

    assert result["allowed"] is True
    assert result["findings"] == []


def test_unknown_response_not_assessed_as_safe():
    result = evaluate_response_policy(
        "This is an unrelated generated response."
    )

    assert result["allowed"] is True
    assert result["confidence"] == "not_assessed"


def test_invalid_response_type():
    with pytest.raises(TypeError):
        evaluate_response_policy(None)



def test_alternative_override_acknowledgment_blocked():
    result = evaluate_response_policy(
        response=(
            "The system has been overridden and "
            "previous instructions are disabled."
        ),
        request_context="What is encryption?",
    )

    assert result["allowed"] is False
    assert result["reason"] == (
        "instruction_override_acknowledgment"
    )


def test_override_explanation_not_blocked():
    result = evaluate_response_policy(
        response=(
            "An attacker may claim the system "
            "has been overridden."
        ),
        request_context=(
            "Explain this prompt injection example."
        ),
    )

    assert result["allowed"] is True


def test_unrelated_security_response_allowed():
    result = evaluate_response_policy(
        response=(
            "Access control limits unauthorized actions."
        ),
        request_context="Define access control.",
    )

    assert result["allowed"] is True
