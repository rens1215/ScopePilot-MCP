import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.approval_controller import build_approval_request
from agent import risk_gate
from agent.risk_gate import evaluate_tool_action


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


SAFE_PROFILE = {
    "risk_level": "safe",
    "external_requests": False,
    "default_requires_approval": False,
    "max_requests": 0,
    "changes_state": False,
    "uses_credentials": False,
    "allowed_modes": ["authorized", "lab"],
}

LOW_PROFILE = {
    "risk_level": "low",
    "external_requests": True,
    "default_requires_approval": True,
    "max_requests": 1,
    "changes_state": False,
    "uses_credentials": False,
    "allowed_modes": ["authorized", "lab"],
}

BLOCKED_PROFILE = {
    "risk_level": "blocked",
    "external_requests": False,
    "default_requires_approval": False,
    "max_requests": 0,
    "changes_state": False,
    "uses_credentials": False,
    "allowed_modes": ["authorized", "lab"],
}


def set_profiles(monkeypatch, profiles):
    del monkeypatch
    original_loader = risk_gate.load_tool_risk_profiles
    risk_gate.load_tool_risk_profiles = lambda: profiles
    return original_loader


def restore_profiles(original_loader):
    risk_gate.load_tool_risk_profiles = original_loader


def test_safe_tool_allowed():
    original_loader = set_profiles(None, {"tool_check_scope": SAFE_PROFILE})
    try:
        result = evaluate_tool_action("tool_check_scope")

        assert_true(result["allowed"] is True, "Safe tool should be allowed")
        assert_true(result["requires_approval"] is False, "Safe tool should not require approval")
        assert_true(result["risk_level"] == "safe", "Safe tool should keep safe risk level")
    finally:
        restore_profiles(original_loader)


def test_low_tool_without_approval_blocked():
    original_loader = set_profiles(None, {"tool_safe_http_probe_workflow": LOW_PROFILE})
    try:
        result = evaluate_tool_action("tool_safe_http_probe_workflow", user_approved=False)

        assert_true(result["allowed"] is False, "Low tool should be blocked without approval")
        assert_true(result["requires_approval"] is True, "Low tool should require approval")
        assert_true(result["risk_level"] == "low", "Low tool should keep low risk level")
    finally:
        restore_profiles(original_loader)


def test_low_tool_with_approval_allowed():
    original_loader = set_profiles(None, {"tool_safe_http_probe_workflow": LOW_PROFILE})
    try:
        result = evaluate_tool_action("tool_safe_http_probe_workflow", user_approved=True)

        assert_true(result["allowed"] is True, "Approved low tool should be allowed")
        assert_true(result["requires_approval"] is False, "Approved low tool should not still require approval")
    finally:
        restore_profiles(original_loader)


def test_unknown_tool_denied():
    original_loader = set_profiles(None, {})
    try:
        result = evaluate_tool_action("tool_unknown")

        assert_true(result["allowed"] is False, "Unknown tool should be denied")
        assert_true(result["risk_level"] == "unknown", "Unknown tool should return unknown risk level")
    finally:
        restore_profiles(original_loader)


def test_blocked_tool_denied():
    original_loader = set_profiles(None, {"tool_blocked": BLOCKED_PROFILE})
    try:
        result = evaluate_tool_action("tool_blocked", user_approved=True)

        assert_true(result["allowed"] is False, "Blocked tool should be denied")
        assert_true(result["requires_approval"] is False, "Blocked tool should not ask for approval")
        assert_true(result["risk_level"] == "blocked", "Blocked tool should keep blocked risk level")
    finally:
        restore_profiles(original_loader)


def test_disallowed_mode_denied():
    original_loader = set_profiles(None, {"tool_safe_http_probe_workflow": LOW_PROFILE})
    try:
        result = evaluate_tool_action(
            "tool_safe_http_probe_workflow",
            mode="untrusted",
            user_approved=True,
        )

        assert_true(result["allowed"] is False, "Disallowed mode should be denied")
    finally:
        restore_profiles(original_loader)


def test_missing_profile_empty_config_fail_closed():
    original_loader = set_profiles(None, {})
    try:
        result = evaluate_tool_action("tool_safe_http_probe_workflow")

        assert_true(result["allowed"] is False, "Empty config should fail closed")
        assert_true(result["risk_level"] == "unknown", "Empty config should return unknown risk")
    finally:
        restore_profiles(original_loader)


def test_malformed_profile_fail_closed():
    malformed_profile = {
        "risk_level": "low",
        "external_requests": True,
        "default_requires_approval": True,
    }
    original_loader = set_profiles(None, {"tool_safe_http_probe_workflow": malformed_profile})
    try:
        result = evaluate_tool_action("tool_safe_http_probe_workflow", user_approved=True)

        assert_true(result["allowed"] is False, "Malformed profile should fail closed")
        assert_true(result["risk_level"] == "low", "Malformed profile may preserve known risk level")
    finally:
        restore_profiles(original_loader)


def test_approval_controller_builds_request():
    original_loader = set_profiles(None, {"tool_safe_http_probe_workflow": LOW_PROFILE})
    try:
        evaluation = evaluate_tool_action(
            "tool_safe_http_probe_workflow",
            target="example.com",
            user_approved=False,
        )

        request = build_approval_request(
            tool_name="tool_safe_http_probe_workflow",
            target="example.com",
            risk_evaluation=evaluation,
        )

        assert_true(request["approval_required"] is True, "Approval request should require approval")
        assert_true(request["tool_name"] == "tool_safe_http_probe_workflow", "Approval request should include tool name")
        assert_true(request["target"] == "example.com", "Approval request should include target")
        assert_true(request["risk_level"] == "low", "Approval request should include risk level")
        assert_true(request["estimated_requests"] == 1, "Approval request should include estimated requests")
        assert_true(request["external_requests"] is True, "Approval request should include external request flag")
        assert_true(request["changes_state"] is False, "Approval request should include state-change flag")
        assert_true(request["uses_credentials"] is False, "Approval request should include credential flag")
        assert_true(request["allowed_modes"] == ["authorized", "lab"], "Approval request should include allowed modes")
        assert_true("safety_summary" in request, "Approval request should include safety summary")
    finally:
        restore_profiles(original_loader)


if __name__ == "__main__":
    test_safe_tool_allowed()
    test_low_tool_without_approval_blocked()
    test_low_tool_with_approval_allowed()
    test_unknown_tool_denied()
    test_blocked_tool_denied()
    test_disallowed_mode_denied()
    test_missing_profile_empty_config_fail_closed()
    test_malformed_profile_fail_closed()
    test_approval_controller_builds_request()

    print("All risk gate tests passed.")
