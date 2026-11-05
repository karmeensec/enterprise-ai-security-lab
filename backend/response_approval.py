
"""
Experiment 50.2 — Response Approval Workflow.

Provides approval and rejection state transitions
for simulation-only incident response plans.

This module does not authenticate reviewers,
persist decisions, or execute response actions.
Those controls belong to the API integration.
"""

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from backend.response_policy_engine import RESPONSE_ACTIONS


MAX_REVIEWER_LENGTH = 128
MAX_NOTES_LENGTH = 2000


class ResponseApprovalError(ValueError):
    """Raised when a response approval is invalid."""


def _validate_text(
    value: str,
    field_name: str,
    max_length: int,
) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > max_length
        or any(ord(char) < 32 for char in value)
    ):
        raise ResponseApprovalError(
            f"Invalid {field_name}"
        )

    return value.strip()


def review_response_plan(
    plan: dict[str, Any],
    reviewer: str,
    decision: str,
    notes: str,
) -> dict[str, Any]:
    """
    Approve or reject a simulation-only response plan.

    Preconditions:
      - Plan uses a known response action.
      - Action requires approval.
      - Plan is pending approval.
      - Plan has never been executed.
      - Decision is approve or reject.
      - Reviewer and notes are validated.

    Returns a new dictionary without mutating the
    original plan.

    Reviewer identity must be obtained from an
    authenticated server-side session in a later step.
    """

    if not isinstance(plan, dict):
        raise ResponseApprovalError(
            "Invalid response plan"
        )

    try:
        UUID(plan["plan_id"])
        UUID(plan["case_id"])
    except (
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
    ) as exc:
        raise ResponseApprovalError(
            "Invalid response plan identifiers"
        ) from exc

    action = plan.get("action")

    if (
        not isinstance(action, str)
        or action not in RESPONSE_ACTIONS
    ):
        raise ResponseApprovalError(
            "Unknown response action"
        )

    policy = RESPONSE_ACTIONS[action]

    if (
        not policy["requires_approval"]
        or plan.get("requires_approval") is not True
    ):
        raise ResponseApprovalError(
            "Action does not require approval"
        )

    if plan.get("status") != "pending_approval":
        raise ResponseApprovalError(
            "Plan is not pending approval"
        )

    if (
        plan.get("execution_mode") != "simulation_only"
        or plan.get("executed") is not False
        or plan.get("policy_decision") != "approval_required"
        or plan.get("risk_level") != policy["risk_level"]
    ):
        raise ResponseApprovalError(
            "Invalid response plan security state"
        )

    if decision not in {"approve", "reject"}:
        raise ResponseApprovalError(
            "Decision must be approve or reject"
        )

    reviewer = _validate_text(
        reviewer,
        "reviewer",
        MAX_REVIEWER_LENGTH,
    )

    notes = _validate_text(
        notes,
        "approval notes",
        MAX_NOTES_LENGTH,
    )

    updated_plan = deepcopy(plan)

    reviewed_at = datetime.now(
        timezone.utc
    ).isoformat()

    if decision == "approve":
        updated_plan["status"] = (
            "approved_for_simulation"
        )
    else:
        updated_plan["status"] = "rejected"

    updated_plan["approval"] = {
        "decision": decision,
        "reviewer": reviewer,
        "notes": notes,
        "reviewed_at": reviewed_at,
    }

    updated_plan["executed"] = False

    # Approval grants permission to proceed to a
    # future simulation step. It does not execute
    # anything or grant access to a real system.

    return updated_plan
