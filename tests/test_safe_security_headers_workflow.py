import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from workflows import safe_security_headers_workflow as workflow_module
from workflows.safe_security_headers_workflow import safe_security_headers_workflow


def assert_true(condition, message):
    """
    Assert safe security headers workflow behavior without real network traffic.

    Tests patch scope checks, the security header helper, storage, logging,
    endpoint classification, and validation. No test sends external requests.
    """
    if not condition:
        raise AssertionError(message)


def patch_workflow(scope_checker, header_checker, saved_findings=None):
    original_scope = workflow_module.check_scope
    original_checker = workflow_module.security_headers_check
    original_save = workflow_module.save_finding
    original_log = workflow_module.log_event
    original_classifier = workflow_module.classify_endpoint
    original_validator = workflow_module.validate_security_headers

    if saved_findings is None:
        saved_findings = []

    def fake_save(finding):
        saved_findings.append(finding)
        return {"saved": True, "path": "mock://findings"}

    def fake_validator(header_result, classification):
        missing = header_result.get("missing", [])
        status = "candidate_finding" if missing else "observation"
        return {
            "status": status,
            "severity": "low" if missing else "info",
            "confidence": "medium",
            "should_report": False,
            "reason": "mock validator",
            "false_positive_notes": [],
        }

    workflow_module.check_scope = scope_checker
    workflow_module.security_headers_check = header_checker
    workflow_module.save_finding = fake_save
    workflow_module.log_event = lambda message: None
    workflow_module.classify_endpoint = lambda probe: {
        "classification": "frontend",
        "confidence": "high",
        "reason": "mock classifier",
    }
    workflow_module.validate_security_headers = fake_validator

    return (
        original_scope,
        original_checker,
        original_save,
        original_log,
        original_classifier,
        original_validator,
        saved_findings,
    )


def restore_workflow(originals):
    (
        original_scope,
        original_checker,
        original_save,
        original_log,
        original_classifier,
        original_validator,
        _saved_findings,
    ) = originals
    workflow_module.check_scope = original_scope
    workflow_module.security_headers_check = original_checker
    workflow_module.save_finding = original_save
    workflow_module.log_event = original_log
    workflow_module.classify_endpoint = original_classifier
    workflow_module.validate_security_headers = original_validator


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


def header_response(target):
    return {
        "target": target,
        "url": "https://example.com/",
        "status_code": 200,
        "blocked": False,
        "present": {
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "set-cookie": "session=secret-cookie",
            "authorization": "Bearer secret-token",
            "x-api-token": "secret-token",
            "x-secret-value": "secret-value",
        },
        "missing": ["content-security-policy", "x-frame-options", "set-cookie"],
        "severity": "low",
        "note": "mock note",
        "probe": {
            "title": "Example",
            "content_type": "text/html; charset=utf-8",
            "body_size": 123,
            "headers": {
                "content-type": "text/html; charset=utf-8",
                "set-cookie": "session=secret-cookie",
                "authorization": "Bearer secret-token",
                "x-api-token": "secret-token",
                "x-secret-value": "secret-value",
            },
            "body": "FULL_SECRET_RESPONSE_BODY",
        },
    }


def test_out_of_scope_stops_without_requests():
    """Protects scope-first behavior and zero requests for out-of-scope targets."""
    calls = []

    def fake_checker(target):
        calls.append(target)
        return header_response(target)

    originals = patch_workflow(out_of_scope, fake_checker)
    try:
        result = safe_security_headers_workflow("evil.test")

        assert_true(result["stopped"] is True, "Out-of-scope target should stop")
        assert_true(result["safety"]["requests_sent"] == 0, "Out-of-scope target should send 0 requests")
        assert_true(calls == [], "Header helper should not be called out of scope")
    finally:
        restore_workflow(originals)


def test_in_scope_calls_security_headers_check_once():
    """Protects the one-request budget for in-scope security header checks."""
    calls = []

    def fake_checker(target):
        calls.append(target)
        return header_response(target)

    originals = patch_workflow(in_scope, fake_checker)
    try:
        result = safe_security_headers_workflow("https://example.com")

        assert_true(calls == ["https://example.com"], "Header helper should be called exactly once")
        assert_true(result["safety"]["requests_sent"] == 1, "requests_sent should be 1")
        assert_true(result["summary"]["max_requests"] == 1, "Summary should expose max request budget")
    finally:
        restore_workflow(originals)


def test_security_headers_check_exception_does_not_crash():
    """Protects workflow stability when security_headers_check raises."""
    calls = []

    def raising_checker(target):
        calls.append(target)
        raise RuntimeError("simulated header failure")

    originals = patch_workflow(in_scope, raising_checker)
    try:
        result = safe_security_headers_workflow("https://example.com")
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true(result["stopped"] is False, "Workflow should not crash on helper exception")
        assert_true("request_error" in statuses, "Helper exception should become request_error")
        assert_true(result["safety"]["requests_sent"] == 1, "Attempted helper call should count once")
        assert_true(calls == ["https://example.com"], "Exception path should still call helper once")
    finally:
        restore_workflow(originals)


def test_security_headers_check_non_dict_does_not_crash():
    """Protects workflow stability when security_headers_check returns malformed data."""
    calls = []

    def malformed_checker(target):
        calls.append(target)
        return "not a dict"

    originals = patch_workflow(in_scope, malformed_checker)
    try:
        result = safe_security_headers_workflow("https://example.com")
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true(result["stopped"] is False, "Workflow should not crash on non-dict helper output")
        assert_true("request_error" in statuses, "Non-dict result should become request_error")
        assert_true(result["safety"]["requests_sent"] == 1, "Malformed helper call should count once")
        assert_true(calls == ["https://example.com"], "Malformed path should still call helper once")
    finally:
        restore_workflow(originals)


def test_safety_metadata_is_low_risk_and_non_destructive():
    """Protects required safety flags for the low-risk security header workflow."""
    originals = patch_workflow(in_scope, header_response)
    try:
        result = safe_security_headers_workflow("https://example.com")
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
    originals = patch_workflow(in_scope, header_response, saved_findings=saved_findings)
    try:
        result = safe_security_headers_workflow("https://example.com")
        result_text = f"{result} {saved_findings}".lower()

        assert_true("strict-transport-security" in result_text, "Safe security header metadata may be retained")
        assert_true("set-cookie" not in result_text, "Set-Cookie header must not be retained")
        assert_true("authorization" not in result_text, "Authorization header must not be retained")
        assert_true("secret-token" not in result_text, "Token-like header values must not be retained")
        assert_true("secret-value" not in result_text, "Secret-like header values must not be retained")
    finally:
        restore_workflow(originals)


def test_full_response_body_is_not_preserved():
    """Protects against storing full response bodies in result or saved finding."""
    saved_findings = []
    originals = patch_workflow(in_scope, header_response, saved_findings=saved_findings)
    try:
        result = safe_security_headers_workflow("https://example.com")
        combined_output = f"{result} {saved_findings}"

        assert_true("FULL_SECRET_RESPONSE_BODY" not in combined_output, "Full response body must not be stored")
        assert_true(saved_findings, "Legacy finding save behavior should be preserved")
    finally:
        restore_workflow(originals)


if __name__ == "__main__":
    test_out_of_scope_stops_without_requests()
    test_in_scope_calls_security_headers_check_once()
    test_security_headers_check_exception_does_not_crash()
    test_security_headers_check_non_dict_does_not_crash()
    test_safety_metadata_is_low_risk_and_non_destructive()
    test_sensitive_headers_are_not_preserved()
    test_full_response_body_is_not_preserved()

    print("All safe security headers workflow tests passed.")
