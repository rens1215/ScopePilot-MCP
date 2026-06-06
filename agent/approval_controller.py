from typing import Any


def build_approval_request(
    tool_name: str,
    target: str | None,
    risk_evaluation: dict[str, Any],
) -> dict[str, Any]:
    """
    Build an approval request object from a risk evaluation result.

    This function does not execute tools, call workflows, or send requests.
    """
    profile = risk_evaluation.get("profile")
    if not isinstance(profile, dict):
        profile = {}

    risk_level = risk_evaluation.get("risk_level", "unknown")
    reason = risk_evaluation.get("reason", "")

    return {
        "approval_required": bool(risk_evaluation.get("requires_approval", False)),
        "tool_name": tool_name,
        "target": target,
        "risk_level": risk_level,
        "reason": reason,
        "estimated_requests": profile.get("max_requests", 0),
        "external_requests": profile.get("external_requests", False),
        "changes_state": profile.get("changes_state", False),
        "uses_credentials": profile.get("uses_credentials", False),
        "allowed_modes": profile.get("allowed_modes", []),
        "safety_summary": {
            "allowed": bool(risk_evaluation.get("allowed", False)),
            "requires_approval": bool(risk_evaluation.get("requires_approval", False)),
            "risk_level": risk_level,
            "reason": reason,
        },
    }
