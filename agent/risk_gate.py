from typing import Any

from tools.policy_loader import load_tool_risk_profiles


VALID_RISK_LEVELS = {"safe", "low", "medium", "high", "blocked"}
APPROVAL_RISK_LEVELS = {"low", "medium", "high"}

REQUIRED_PROFILE_FIELDS = {
    "risk_level": str,
    "external_requests": bool,
    "default_requires_approval": bool,
    "max_requests": int,
    "changes_state": bool,
    "uses_credentials": bool,
    "allowed_modes": list,
}


def _deny(
    reason: str,
    risk_level: str = "unknown",
    profile: dict[str, Any] | None = None,
    requires_approval: bool = False,
) -> dict[str, Any]:
    """Return the standard fail-closed denial shape used by the risk gate."""
    return {
        "allowed": False,
        "requires_approval": requires_approval,
        "reason": reason,
        "risk_level": risk_level,
        "profile": profile or {},
    }


def _validate_profile(profile: Any) -> tuple[bool, str]:
    """
    Validate the minimum policy schema needed for deterministic risk decisions.

    This function only inspects an in-memory profile. It does not execute tools,
    send external requests, call workflows, or modify state.

    Safety boundary: any missing field, unexpected type, invalid risk level, or
    invalid execution mode list is treated as malformed so the caller can deny
    the action by default.
    """
    if not isinstance(profile, dict):
        return False, "Tool risk profile is missing or malformed."

    for field, expected_type in REQUIRED_PROFILE_FIELDS.items():
        if field not in profile:
            # Malformed profile fail-closed: incomplete policy cannot allow use.
            return False, f"Tool risk profile is missing required field: {field}."
        if not isinstance(profile[field], expected_type):
            # Malformed profile fail-closed: type ambiguity cannot allow use.
            return False, f"Tool risk profile field has invalid type: {field}."

    if isinstance(profile["max_requests"], bool) or profile["max_requests"] < 0:
        # bool is an int subclass in Python, so reject it explicitly here.
        return False, "Tool risk profile field has invalid value: max_requests."

    if profile["risk_level"] not in VALID_RISK_LEVELS:
        # Unknown risk labels are not interpreted optimistically.
        return False, "Tool risk profile field has invalid value: risk_level."

    if not all(isinstance(mode, str) for mode in profile["allowed_modes"]):
        # Execution contexts must be explicit strings such as authorized or lab.
        return False, "Tool risk profile field has invalid value: allowed_modes."

    return True, ""


def evaluate_tool_action(
    tool_name: str,
    target: str | None = None,
    mode: str = "authorized",
    user_approved: bool = False,
) -> dict[str, Any]:
    """
    Evaluate whether a tool action is allowed by the risk policy.

    The result is a policy decision object for the named tool and execution
    context. This function only reads risk profile config and returns a
    decision. It never executes tools, calls workflows, sends external requests,
    or modifies runtime state.

    Safety boundary: unknown tools, missing config, malformed profiles, blocked
    tools, disallowed modes, and unapproved low/medium/high tools are denied by
    default. Only safe tools, or approved low/medium/high tools in an allowed
    mode, can return allowed=true.
    """
    del target

    try:
        profiles = load_tool_risk_profiles()
    except Exception:
        # Config loader bugs or unexpected read failures must not crash callers.
        profiles = {}

    if not isinstance(profiles, dict):
        # Fail closed if a patched or future loader returns an invalid shape.
        profiles = {}

    profile = profiles.get(tool_name)
    if profile is None:
        # Unknown tool / missing profile deny by default.
        return _deny("Unknown tool or missing risk profile.")

    is_valid, validation_error = _validate_profile(profile)
    if not is_valid:
        # Malformed profile fail-closed, while preserving a valid known label
        # for audit clarity when possible.
        risk_level = profile.get("risk_level", "unknown") if isinstance(profile, dict) else "unknown"
        if risk_level not in VALID_RISK_LEVELS:
            risk_level = "unknown"
        return _deny(validation_error, risk_level=risk_level, profile=profile if isinstance(profile, dict) else {})

    risk_level = profile["risk_level"]

    if risk_level == "blocked":
        # Blocked tools are never allowed, even with user approval.
        return _deny(
            "Tool is blocked by risk policy.",
            risk_level=risk_level,
            profile=profile,
        )

    if mode not in profile["allowed_modes"]:
        # Authorized risk level is not enough; the execution context must match.
        return _deny(
            "Execution mode is not allowed for this tool.",
            risk_level=risk_level,
            profile=profile,
        )

    if risk_level == "safe":
        # Safe tools are local/non-external by policy and do not need approval.
        return {
            "allowed": True,
            "requires_approval": False,
            "reason": "Safe tool is allowed by policy.",
            "risk_level": risk_level,
            "profile": profile,
        }

    if risk_level in APPROVAL_RISK_LEVELS and not user_approved:
        # Low, medium, and high risk actions require explicit user approval.
        return _deny(
            "Tool requires user approval before execution.",
            risk_level=risk_level,
            profile=profile,
            requires_approval=True,
        )

    if risk_level in APPROVAL_RISK_LEVELS and user_approved:
        # Approval only grants access after profile and mode checks pass above.
        return {
            "allowed": True,
            "requires_approval": False,
            "reason": "Tool is approved for this execution mode.",
            "risk_level": risk_level,
            "profile": profile,
        }

    # Defensive fallback for any future risk level that was not handled above.
    return _deny("Tool risk level is not allowed by policy.", risk_level=risk_level, profile=profile)
