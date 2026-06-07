import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools import result_schema
from tools.result_schema import (
    append_error,
    append_observation,
    build_blocked_result,
    build_workflow_result,
)


def assert_true(condition, message):
    """Assert result schema helper behavior without network or workflow calls."""
    if not condition:
        raise AssertionError(message)


def test_build_workflow_result_has_required_fields():
    """Protects the stable base schema expected by future workflow refactors."""
    result = build_workflow_result()
    required = {
        "target",
        "stopped",
        "reason",
        "scope",
        "observations",
        "inventory_candidates",
        "findings",
        "errors",
        "warnings",
        "summary",
        "safety",
    }

    assert_true(required.issubset(result.keys()), "Workflow result should include all required fields")


def test_build_workflow_result_accepts_target():
    """Protects target propagation into the standard result shape."""
    result = build_workflow_result(target="https://example.com")

    assert_true(result["target"] == "https://example.com", "Target should be preserved")


def test_build_workflow_result_accepts_scope():
    """Protects scope metadata propagation without calling scope_guard."""
    scope = {"in_scope": True, "hostname": "example.com"}
    result = build_workflow_result(scope=scope)

    assert_true(result["scope"] == scope, "Scope metadata should be preserved")


def test_build_blocked_result_sets_stopped_true():
    """Protects blocked results from being mistaken for allowed execution."""
    result = build_blocked_result(target="example.com")

    assert_true(result["stopped"] is True, "Blocked result should be stopped")


def test_build_blocked_result_zero_requests():
    """Protects scope/policy blocked results from implying external requests."""
    result = build_blocked_result(target="example.com")

    assert_true(result["safety"]["requests_sent"] == 0, "Blocked result should report 0 requests")


def test_build_blocked_result_scan_level_blocked():
    """Protects explicit blocked safety metadata."""
    result = build_blocked_result(target="example.com")

    assert_true(result["safety"]["scan_level"] == "blocked", "Blocked result should report scan_level=blocked")


def test_append_observation_adds_observation():
    """Protects observation append behavior for normal result objects."""
    result = build_workflow_result()
    append_observation(result, {"status": "parsed"})

    assert_true(result["observations"] == [{"status": "parsed"}], "Observation should be appended")


def test_append_observation_missing_field_does_not_crash():
    """Protects fail-safe observation append when caller result lacks the key."""
    result = {"target": "example.com", "custom": True}
    append_observation(result, {"status": "parsed"})

    assert_true(result["observations"] == [{"status": "parsed"}], "Missing observations should be initialized")
    assert_true(result["custom"] is True, "Existing caller fields should be preserved")


def test_append_error_accepts_string_error():
    """Protects simple string error append behavior."""
    result = build_workflow_result()
    append_error(result, "request_error")

    assert_true(result["errors"] == ["request_error"], "String error should be appended")


def test_append_error_accepts_dict_error():
    """Protects structured error append behavior."""
    result = build_workflow_result()
    append_error(result, {"type": "request_error", "message": "failed"})

    assert_true(
        result["errors"] == [{"type": "request_error", "message": "failed"}],
        "Dict error should be appended",
    )


def test_append_error_missing_field_does_not_crash():
    """Protects fail-safe error append when caller result lacks the key."""
    result = {"target": "example.com", "custom": True}
    append_error(result, "request_error")

    assert_true(result["errors"] == ["request_error"], "Missing errors should be initialized")
    assert_true(result["custom"] is True, "Existing caller fields should be preserved")


def test_helpers_do_not_call_workflows_or_send_requests():
    """Protects that result schema helpers remain local-only structure builders."""
    assert_true("http_probe" not in result_schema.__dict__, "Result schema helper should not import http_probe")
    assert_true("httpx" not in result_schema.__dict__, "Result schema helper should not import httpx")
    assert_true("requests" not in result_schema.__dict__, "Result schema helper should not import requests")
    assert_true("workflows" not in result_schema.__dict__, "Result schema helper should not import workflows")


if __name__ == "__main__":
    test_build_workflow_result_has_required_fields()
    test_build_workflow_result_accepts_target()
    test_build_workflow_result_accepts_scope()
    test_build_blocked_result_sets_stopped_true()
    test_build_blocked_result_zero_requests()
    test_build_blocked_result_scan_level_blocked()
    test_append_observation_adds_observation()
    test_append_observation_missing_field_does_not_crash()
    test_append_error_accepts_string_error()
    test_append_error_accepts_dict_error()
    test_append_error_missing_field_does_not_crash()
    test_helpers_do_not_call_workflows_or_send_requests()

    print("All result schema tests passed.")
