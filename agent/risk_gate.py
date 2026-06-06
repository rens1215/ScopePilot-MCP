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
    return {
        "allowed": False,
        "requires_approval": requires_approval,
        "reason": reason,
        "risk_level": risk_level,
        "profile": profile or {},
    }


def _validate_profile(profile: Any) -> tuple[bool, str]:
    if not isinstance(profile, dict):
        return False, "Tool risk profile is missing or malformed."

    for field, expected_type in REQUIRED_PROFILE_FIELDS.items():
        if field not in profile:
            return False, f"Tool risk profile is missing required field: {field}."
        if not isinstance(profile[field], expected_type):
            return False, f"Tool risk profile field has invalid type: {field}."

    if isinstance(profile["max_requests"], bool) or profile["max_requests"] < 0:
        return False, "Tool risk profile field has invalid value: max_requests."

    if profile["risk_level"] not in VALID_RISK_LEVELS:
        return False, "Tool risk profile field has invalid value: risk_level."

    if not all(isinstance(mode, str) for mode in profile["allowed_modes"]):
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

    This function only reads risk profile config and returns a decision. It
    never executes tools, calls workflows, or sends external requests.
    """
    del target

    try:
        profiles = load_tool_risk_profiles()
    except Exception:
        profiles = {}

    if not isinstance(profiles, dict):
        profiles = {}

    profile = profiles.get(tool_name)
    if profile is None:
        return _deny("Unknown tool or missing risk profile.")

    is_valid, validation_error = _validate_profile(profile)
    if not is_valid:
        risk_level = profile.get("risk_level", "unknown") if isinstance(profile, dict) else "unknown"
        if risk_level not in VALID_RISK_LEVELS:
            risk_level = "unknown"
        return _deny(validation_error, risk_level=risk_level, profile=profile if isinstance(profile, dict) else {})

    risk_level = profile["risk_level"]

    if risk_level == "blocked":
        return _deny(
            "Tool is blocked by risk policy.",
            risk_level=risk_level,
            profile=profile,
        )

    if mode not in profile["allowed_modes"]:
        return _deny(
            "Execution mode is not allowed for this tool.",
            risk_level=risk_level,
            profile=profile,
        )

    if risk_level == "safe":
        return {
            "allowed": True,
            "requires_approval": False,
            "reason": "Safe tool is allowed by policy.",
            "risk_level": risk_level,
            "profile": profile,
        }

    if risk_level in APPROVAL_RISK_LEVELS and not user_approved:
        return _deny(
            "Tool requires user approval before execution.",
            risk_level=risk_level,
            profile=profile,
            requires_approval=True,
        )

    if risk_level in APPROVAL_RISK_LEVELS and user_approved:
        return {
            "allowed": True,
            "requires_approval": False,
            "reason": "Tool is approved for this execution mode.",
            "risk_level": risk_level,
            "profile": profile,
        }

    return _deny("Tool risk level is not allowed by policy.", risk_level=risk_level, profile=profile)
