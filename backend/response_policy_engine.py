
"""
Experiment 50 — Incident Response Action Policy Engine.

Creates safe response recommendations for investigation cases.

This module does NOT execute actions against real systems.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4


RESPONSE_ACTIONS = {
    "review_audit_logs": {
        "description": "Review related security audit events",
        "risk_level": "low",
        "requires_approval": False,
    },
    "verify_policy_integrity": {
        "description": "Verify knowledge-base integrity",
        "risk_level": "low",
        "requires_approval": False,
    },
    "collect_evidence": {
        "description": "Collect approved investigation evidence",
        "risk_level": "low",
        "requires_approval": False,
    },
    "isolate_service": {
        "description": "Simulate isolation of an affected service",
        "risk_level": "high",
        "requires_approval": True,
    },
    "disable_account": {
        "description": "Simulate disabling a potentially affected account",
        "risk_level": "high",
        "requires_approval": True,
    },
    "revoke_credentials": {
        "description": "Simulate revoking potentially exposed credentials",
        "risk_level": "critical",
        "requires_approval": True,
    },
    "restore_trusted_policies": {
        "description": "Simulate restoring an approved policy baseline",
        "risk_level": "critical",
        "requires_approval": True,
    },
}

ALLOWED_CASE_STATUSES = {
    "open",
    "investigating",
}

MAX_TARGET_LENGTH = 128


class ResponsePolicyError(ValueError):
    """Raised when a response request fails validation."""


def _validate_case_id(case_id: str) -> None:
    if not isinstance(case_id, str):
        raise ResponsePolicyError("Invalid case ID")

    try:
        UUID(case_id)
    except ValueError as exc:
        raise ResponsePolicyError(
            "Case ID must be a UUID"
        ) from exc


def create_response_plan(
    case_id: str,
    case_status: str,
    action: str,
    target: str | None = None,
) -> dict[str, Any]:
    """
    Evaluate a proposed incident response action.

    Returns a response plan but never executes the action.

    High-risk and critical actions require a future
    authenticated approval workflow.
    """

    _validate_case_id(case_id)

    if case_status not in ALLOWED_CASE_STATUSES:
        raise ResponsePolicyError(
            "Response actions require an open or investigating case"
        )

    if not isinstance(action, str):
        raise ResponsePolicyError(
            "Invalid response action"
        )

    action_policy = RESPONSE_ACTIONS.get(action)

    if action_policy is None:
        raise ResponsePolicyError(
            "Unsupported response action"
        )

    if target is not None:
        if (
            not isinstance(target, str)
            or not target.strip()
            or len(target) > MAX_TARGET_LENGTH
            or any(ord(char) < 32 for char in target)
        ):
            raise ResponsePolicyError(
                "Invalid response target"
            )

        target = target.strip()

    if action_policy["requires_approval"]:
        status = "pending_approval"
        decision = "approval_required"
    else:
        status = "proposed"
        decision = "eligible_for_simulation"

    return {
        "plan_id": str(uuid4()),
        "case_id": case_id,
        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "action": action,
        "description": action_policy["description"],
        "target": target,
        "risk_level": action_policy["risk_level"],
        "requires_approval": action_policy["requires_approval"],
        "policy_decision": decision,
        "status": status,
        "execution_mode": "simulation_only",
        "executed": False,
    }


def list_response_actions() -> list[dict[str, Any]]:
    """Return the supported response action catalog."""

    return [
        {
            "action": action,
            **policy,
        }
        for action, policy in RESPONSE_ACTIONS.items()
    ]
