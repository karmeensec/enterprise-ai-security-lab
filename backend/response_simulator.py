
"""
Experiment 50.5 — Safe Incident Response Simulator.

Generates simulated incident-response outcomes.

SECURITY:
- No shell commands.
- No subprocesses.
- No network calls.
- No operating-system modifications.
- No actual account, service, or policy changes.

The caller must obtain plans from the trusted response-plan
store. This module alone cannot authenticate an approver.
"""

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from backend.response_policy_engine import RESPONSE_ACTIONS


class ResponseSimulationError(ValueError):
    """Raised when a plan is not eligible for simulation."""


SIMULATION_DESCRIPTIONS = {
    "review_audit_logs": (
        "Simulated review of related security audit records. "
        "No audit files were opened or modified."
    ),
    "verify_policy_integrity": (
        "Simulated verification of the approved policy baseline. "
        "No policy files were accessed or modified."
    ),
    "collect_evidence": (
        "Simulated collection of investigation evidence. "
        "No files or external systems were accessed."
    ),
    "isolate_service": (
        "Simulated isolation of an affected service. "
        "No service or network configuration was changed."
    ),
    "disable_account": (
        "Simulated disabling of an affected account. "
        "No identity provider or account was modified."
    ),
    "revoke_credentials": (
        "Simulated revocation of exposed credentials. "
        "No credentials, sessions, or tokens were revoked."
    ),
    "restore_trusted_policies": (
        "Simulated restoration of a trusted policy baseline. "
        "No policy files were restored or overwritten."
    ),
}


def _validate_uuid(value: Any, field: str) -> None:
    if not isinstance(value, str):
        raise ResponseSimulationError(
            f"Invalid {field}"
        )

    try:
        UUID(value)
    except ValueError as exc:
        raise ResponseSimulationError(
            f"Invalid {field}"
        ) from exc


def _validate_plan(plan: dict[str, Any]) -> dict:
    if not isinstance(plan, dict):
        raise ResponseSimulationError(
            "Invalid response plan"
        )

    _validate_uuid(
        plan.get("plan_id"),
        "plan ID",
    )

    _validate_uuid(
        plan.get("case_id"),
        "case ID",
    )

    action = plan.get("action")

    if (
        not isinstance(action, str)
        or action not in RESPONSE_ACTIONS
    ):
        raise ResponseSimulationError(
            "Unsupported response action"
        )

    policy = RESPONSE_ACTIONS[action]

    if (
        plan.get("execution_mode") != "simulation_only"
        or plan.get("executed") is not False
    ):
        raise ResponseSimulationError(
            "Invalid simulation security state"
        )

    if (
        plan.get("risk_level") != policy["risk_level"]
        or plan.get("requires_approval")
        is not policy["requires_approval"]
    ):
        raise ResponseSimulationError(
            "Response policy mismatch"
        )

    if policy["requires_approval"]:
        if (
            plan.get("status")
            != "approved_for_simulation"
            or plan.get("policy_decision")
            != "approval_required"
        ):
            raise ResponseSimulationError(
                "Approved response plan required"
            )

        approval = plan.get("approval")

        if (
            not isinstance(approval, dict)
            or approval.get("decision") != "approve"
            or not isinstance(
                approval.get("reviewer"), str
            )
            or not approval["reviewer"].strip()
            or not isinstance(
                approval.get("notes"), str
            )
            or not approval["notes"].strip()
            or not isinstance(
                approval.get("reviewed_at"), str
            )
        ):
            raise ResponseSimulationError(
                "Valid approval record required"
            )

    else:
        if (
            plan.get("status") != "proposed"
            or plan.get("policy_decision")
            != "eligible_for_simulation"
            or plan.get("approval") is not None
        ):
            raise ResponseSimulationError(
                "Invalid low-risk response state"
            )

    target = plan.get("target")

    if target is not None and (
        not isinstance(target, str)
        or not target.strip()
        or len(target) > 128
        or any(ord(char) < 32 for char in target)
    ):
        raise ResponseSimulationError(
            "Invalid response target"
        )

    return policy


def simulate_response_plan(
    plan: dict[str, Any],
) -> dict[str, Any]:
    """
    Produce a simulated response result.

    This function does not execute any real response
    action or write to the filesystem.

    The original plan is not modified.
    """

    _validate_plan(plan)

    action = plan["action"]
    policy = RESPONSE_ACTIONS[action]

    result = {
        "simulation_id": str(uuid4()),
        "plan_id": plan["plan_id"],
        "case_id": plan["case_id"],
        "action": action,
        "risk_level": policy["risk_level"],
        "simulation_status": "completed",
        "execution_mode": "simulation_only",
        "real_action_executed": False,
        "simulated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "target": plan.get("target"),
        "summary": SIMULATION_DESCRIPTIONS[action],
        "safeguards": {
            "shell_execution": False,
            "network_requests": False,
            "system_modification": False,
            "credential_modification": False,
        },
    }

    return deepcopy(result)
