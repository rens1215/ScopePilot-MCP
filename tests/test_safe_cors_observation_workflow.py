import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from workflows import safe_cors_observation_workflow as workflow_module
from workflows.safe_cors_observation_workflow import (
    DEFAULT_TEST_ORIGIN,
    safe_cors_observation_workflow,
)


def assert_true(condition, message):
    """
    Assert safe CORS observation workflow behavior without real network traffic.

    Tests patch scope checks, the CORS request helper, storage, logging,
    endpoint classification, and validation. No test sends external requests.
    """
    if not condition:
        raise AssertionError(message)


def patch_workflow(scope_checker, cors_helper, saved_findings=None):
    original_scope = workflow_module.check_scope
    original_helper = workflow_module._cors_observation_request
    original_save = workflow_module.save_finding
    original_log = workflow_module.log_event
    original_classifier = workflow_module.classify_endpoint
    original_validator = workflow_module.validate_cors

    if saved_findings is None:
        saved_findings = []

    def fake_save(finding):
        saved_findings.append(finding)
        return {"saved": True, "path": "mock://findings"}

    def fake_validator(cors_result, classification):
        status = "candidate_finding" if cors_result.get("origin_reflected") else "observation"
        return {
            "status": status,
            "severity": "low" if status == "candidate_finding" else "info",
            "confidence": "medium",
            "should_report": False,
            "reason": "mock validator",
            "false_positive_notes": [],
        }

    workflow_module.check_scope = scope_checker
    workflow_module._cors_observation_request = cors_helper
    workflow_module.save_finding = fake_save
    workflow_module.log_event = lambda message: None
    workflow_module.classify_endpoint = lambda probe: {
        "classification": "frontend",
        "confidence": "high",
        "reason": "mock classifier",
    }
    workflow_module.validate_cors = fake_validator

    return (
        original_scope,
        original_helper,
        original_save,
        original_log,
        original_classifier,
        original_validator,
        saved_findings,
    )


def restore_workflow(originals):
    (
        original_scope,
        original_helper,
        original_save,
        original_log,
        original_classifier,
        original_validator,
        _saved_findings,
    ) = originals
    workflow_module.check_scope = original_scope
    workflow_module._cors_observation_request = original_helper
    workflow_module.save_finding = original_save
    workflow_module.log_event = original_log
    workflow_module.classify_endpoint = original_classifier
    workflow_module.validate_cors = original_validator


def scope_result(target, in_scope=True):
    return {
        "target": target,
        "hostname": "example.com" if in_scope else "evil.test",
        "in_scope": in_scope,
        "reason": "test scope" if in_scope else "test out of scope",
        "allowed_scan_level": "passive_or_light" if in_scope else "forbidden",
    }


def in_scope(target):
    return scope_result(target, in_scope=True)


def out_of_scope(target):
    return scope_result(target, in_scope=False)


def cors_response(target, url, test_origin):
    return {
        "target": target,
        "url": "https://example.com/",
        "blocked": False,
        "status_code": 200,
        "final_url": "https://example.com/",
        "redirect_history": [],
        "headers": {
            "content-type": "text/html; charset=utf-8",
            "access-control-allow-origin": test_origin,
            "access-control-allow-credentials": "true",
            "access-control-allow-methods": "GET",
            "access-control-allow-headers": "authorization, x-api-token",
            "set-cookie": "session=secret-cookie",
            "authorization": "Bearer secret-token",
            "x-api-token": "secret-token",
            "x-secret-value": "secret-value",
        },
        "cors_headers": {
            "access-control-allow-origin": test_origin,
            "access-control-allow-credentials": "true",
            "access-control-allow-methods": "GET",
            "access-control-allow-headers": "authorization, x-api-token",
            "access-control-expose-headers": None,
            "vary": "Origin",
        },
        "origin_tested": test_origin,
        "origin_reflected": True,
        "content_type": "text/html; charset=utf-8",
        "title": "Example",
        "body_size": 123,
        "body": "FULL_SECRET_RESPONSE_BODY",
    }


def test_out_of_scope_stops_without_requests():
    """Protects scope-first behavior and zero requests for out-of-scope targets."""
    calls = []

    def fake_helper(target, url, test_origin):
        calls.append((target, url, test_origin))
        return cors_response(target, url, test_origin)

    originals = patch_workflow(out_of_scope, fake_helper)
    try:
        result = safe_cors_observation_workflow("evil.test")

        assert_true(result["stopped"] is True, "Out-of-scope target should stop")
        assert_true(result["safety"]["requests_sent"] == 0, "Out-of-scope target should send 0 requests")
        assert_true(calls == [], "CORS helper should not be called out of scope")
    finally:
        restore_workflow(originals)


def test_in_scope_calls_cors_helper_once():
    """Protects the one-request budget for in-scope CORS observation."""
    calls = []

    def fake_helper(target, url, test_origin):
        calls.append((target, url, test_origin))
        return cors_response(target, url, test_origin)

    originals = patch_workflow(in_scope, fake_helper)
    try:
        result = safe_cors_observation_workflow("https://example.com")

        assert_true(len(calls) == 1, "CORS helper should be called exactly once")
        assert_true(result["safety"]["requests_sent"] == 1, "requests_sent should be 1")
        assert_true(result["summary"]["max_requests"] == 1, "Summary should expose max request budget")
    finally:
        restore_workflow(originals)


def test_cors_helper_exception_does_not_crash():
    """Protects workflow stability when the CORS observation helper raises."""
    calls = []

    def raising_helper(target, url, test_origin):
        calls.append((target, url, test_origin))
        raise RuntimeError("simulated cors failure")

    originals = patch_workflow(in_scope, raising_helper)
    try:
        result = safe_cors_observation_workflow("https://example.com")
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true(result["stopped"] is False, "Workflow should not crash on helper exception")
        assert_true("request_error" in statuses, "Helper exception should become request_error")
        assert_true(result["safety"]["requests_sent"] == 1, "Attempted helper call should count once")
        assert_true(len(calls) == 1, "Exception path should still call helper once")
    finally:
        restore_workflow(originals)


def test_cors_helper_non_dict_does_not_crash():
    """Protects workflow stability when the CORS helper returns malformed data."""
    calls = []

    def malformed_helper(target, url, test_origin):
        calls.append((target, url, test_origin))
        return "not a dict"

    originals = patch_workflow(in_scope, malformed_helper)
    try:
        result = safe_cors_observation_workflow("https://example.com")
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true(result["stopped"] is False, "Workflow should not crash on non-dict helper output")
        assert_true("request_error" in statuses, "Non-dict result should become request_error")
        assert_true(result["safety"]["requests_sent"] == 1, "Malformed helper call should count once")
        assert_true(len(calls) == 1, "Malformed path should still call helper once")
    finally:
        restore_workflow(originals)


def test_safety_metadata_is_low_risk_and_non_destructive():
    """Protects required safety flags for the low-risk CORS workflow."""
    originals = patch_workflow(in_scope, cors_response)
    try:
        result = safe_cors_observation_workflow("https://example.com")
        safety = result.get("safety", {})

        assert_true(safety["scan_level"] == "low-risk", "Workflow should be low-risk")
        assert_true(safety["requests_sent"] <= 1, "Workflow must not exceed one request")
        assert_true(safety["fuzzing"] is False, "Workflow should not fuzz")
        assert_true(safety["bruteforce"] is False, "Workflow should not brute force")
        assert_true(safety["exploitation"] is False, "Workflow should not exploit")
        assert_true(safety["crawling"] is False, "Workflow should not crawl")
        assert_true(safety["credentialed_request"] is False, "Workflow should not use credentials")
    finally:
        restore_workflow(originals)


def test_sensitive_headers_are_not_preserved():
    """Protects minimization of sensitive header names and values."""
    saved_findings = []
    originals = patch_workflow(in_scope, cors_response, saved_findings=saved_findings)
    try:
        result = safe_cors_observation_workflow("https://example.com")
        result_text = f"{result} {saved_findings}".lower()

        assert_true("access-control-allow-origin" in result_text, "Safe CORS metadata may be retained")
        assert_true("set-cookie" not in result_text, "Set-Cookie header must not be retained")
        assert_true("authorization" not in result_text, "Authorization header must not be retained")
        assert_true("secret-token" not in result_text, "Token-like values must not be retained")
        assert_true("secret-value" not in result_text, "Secret-like values must not be retained")
    finally:
        restore_workflow(originals)


def test_full_response_body_is_not_preserved():
    """Protects against storing full response bodies in result or saved finding."""
    saved_findings = []
    originals = patch_workflow(in_scope, cors_response, saved_findings=saved_findings)
    try:
        result = safe_cors_observation_workflow("https://example.com")
        combined_output = f"{result} {saved_findings}"

        assert_true("FULL_SECRET_RESPONSE_BODY" not in combined_output, "Full response body must not be stored")
        assert_true(saved_findings, "Legacy finding save behavior should be preserved")
    finally:
        restore_workflow(originals)


def test_test_origin_is_harmless_and_credential_free():
    """Protects that test_origin output does not preserve credential-like values."""
    calls = []
    saved_findings = []

    def fake_helper(target, url, test_origin):
        calls.append((target, url, test_origin))
        return cors_response(target, url, test_origin)

    originals = patch_workflow(in_scope, fake_helper, saved_findings=saved_findings)
    try:
        result = safe_cors_observation_workflow(
            "https://example.com",
            test_origin="https://user:token-secret@example-attacker.invalid",
        )
        combined_output = f"{result} {saved_findings}".lower()

        assert_true(calls[0][2] == DEFAULT_TEST_ORIGIN, "Credential-like origin should be replaced by default")
        assert_true("user:token-secret" not in combined_output, "Credential-like origin must not be saved")
        assert_true(result["cors_summary"]["origin_tested"] == DEFAULT_TEST_ORIGIN, "Summary should use safe origin")
    finally:
        restore_workflow(originals)


if __name__ == "__main__":
    test_out_of_scope_stops_without_requests()
    test_in_scope_calls_cors_helper_once()
    test_cors_helper_exception_does_not_crash()
    test_cors_helper_non_dict_does_not_crash()
    test_safety_metadata_is_low_risk_and_non_destructive()
    test_sensitive_headers_are_not_preserved()
    test_full_response_body_is_not_preserved()
    test_test_origin_is_harmless_and_credential_free()

    print("All safe CORS observation workflow tests passed.")
