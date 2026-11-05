
"""
Experiment 52 — AI Agent Tool-Call Security.

Deterministic authorization for proposed AI agent tool calls.

The LLM is untrusted:
- It cannot assign its own role.
- It cannot choose its own authorized case.
- It cannot override tool permissions.
- It cannot execute arbitrary functions.
- It cannot pass unexpected tool arguments.

This module only evaluates tool requests.
It does not perform any tool calls.
"""

import json
import re
from dataclasses import dataclass
from typing import Any


MAX_ARGUMENT_BYTES = 4096

CASE_ID_PATTERN = re.compile(
    r"^[0-9a-fA-F-]{36}$"
)

TOOL_REGISTRY = {
    "search_security_policies": {
        "allowed_roles": {"analyst", "admin"},
        "required_args": {"query"},
        "optional_args": set(),
        "risk": "low",
    },
    "get_incident_timeline": {
        "allowed_roles": {"analyst", "admin"},
        "required_args": {"case_id"},
        "optional_args": set(),
        "risk": "low",
    },
    "list_response_plans": {
        "allowed_roles": {"analyst", "admin"},
        "required_args": {"case_id"},
        "optional_args": set(),
        "risk": "low",
    },
    "propose_response_action": {
        "allowed_roles": {"analyst", "admin"},
        "required_args": {"case_id", "action"},
        "optional_args": {"target"},
        "risk": "high",
    },
}

RESPONSE_ACTIONS = {
    "review_audit_logs",
    "verify_policy_integrity",
    "collect_evidence",
    "isolate_service",
    "disable_account",
    "revoke_credentials",
    "restore_trusted_policies",
}


@dataclass(frozen=True)
class AgentSecurityContext:
    """
    Trusted security context supplied by the server.

    Never construct this from LLM-generated arguments.
    """

    principal_id: str
    role: str
    authorized_case_ids: frozenset[str]


def _deny(reason: str) -> dict[str, Any]:
    return {
        "allowed": False,
        "decision": "blocked",
        "reason": reason,
        "execution_permitted": False,
        "normalized_arguments": None,
    }


def authorize_agent_tool_call(
    tool_name: str,
    arguments: Any,
    context: AgentSecurityContext,
) -> dict[str, Any]:
    """
    Validate a proposed tool call against server-side policy.

    Returns a normalized request when permitted.

    A permitted decision is NOT permission to execute
    arbitrary code or bypass downstream authorization.
    """

    if not isinstance(context, AgentSecurityContext):
        return _deny("Missing trusted security context")

    if (
        not isinstance(context.principal_id, str)
        or not context.principal_id.strip()
        or context.role not in {"analyst", "admin"}
        or not isinstance(
            context.authorized_case_ids,
            frozenset,
        )
        or not all(
            isinstance(item, str)
            for item in context.authorized_case_ids
        )
    ):
        return _deny("Invalid trusted security context")

    if not isinstance(tool_name, str):
        return _deny("Invalid tool name")

    policy = TOOL_REGISTRY.get(tool_name)

    if policy is None:
        return _deny("Tool is not registered")

    if context.role not in policy["allowed_roles"]:
        return _deny("Insufficient tool permissions")

    if not isinstance(arguments, dict):
        return _deny("Tool arguments must be an object")

    try:
        encoded = json.dumps(
            arguments,
            allow_nan=False,
        )
    except (TypeError, ValueError, OverflowError):
        return _deny("Invalid tool argument encoding")

    if len(encoded.encode("utf-8")) > MAX_ARGUMENT_BYTES:
        return _deny("Tool arguments exceed size limit")

    keys = set(arguments)

    allowed_keys = (
        policy["required_args"]
        | policy["optional_args"]
    )

    if not keys.issubset(allowed_keys):
        return _deny("Unexpected tool arguments")

    if not policy["required_args"].issubset(keys):
        return _deny("Missing required tool arguments")

    normalized = {}

    if "query" in arguments:
        query = arguments["query"]

        if (
            not isinstance(query, str)
            or not 1 <= len(query.strip()) <= 500
            or any(ord(c) < 32 for c in query)
        ):
            return _deny("Invalid policy search query")

        normalized["query"] = query.strip()

    if "case_id" in arguments:
        case_id = arguments["case_id"]

        if (
            not isinstance(case_id, str)
            or not CASE_ID_PATTERN.fullmatch(case_id)
        ):
            return _deny("Invalid case identifier")

        if case_id not in context.authorized_case_ids:
            return _deny("Case access denied")

        normalized["case_id"] = case_id

    if "action" in arguments:
        action = arguments["action"]

        if (
            not isinstance(action, str)
            or action not in RESPONSE_ACTIONS
        ):
            return _deny("Unsupported response action")

        normalized["action"] = action

    if "target" in arguments:
        target = arguments["target"]

        if (
            not isinstance(target, str)
            or not target.strip()
            or len(target) > 128
            or any(ord(c) < 32 for c in target)
        ):
            return _deny("Invalid response target")

        normalized["target"] = target.strip()

    return {
        "allowed": True,
        "decision": "authorized_proposal",
        "reason": "Tool request satisfies authorization policy",
        "tool_name": tool_name,
        "risk": policy["risk"],
        "principal_id": context.principal_id,
        "normalized_arguments": normalized,
        "execution_permitted": False,
    }
