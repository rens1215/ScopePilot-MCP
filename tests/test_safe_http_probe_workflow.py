import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from workflows import safe_http_probe_workflow as workflow_module
from workflows.safe_http_probe_workflow import safe_http_probe_workflow


def assert_true(condition, message):
    """
    Assert safe HTTP probe workflow behavior without real network traffic.

    Tests patch scope checks, HTTP probing, finding storage, classification, and
    logging so every safety boundary is verified with local mock data only.
    """
    if not condition:
        raise AssertionError(message)


def patch_workflow(scope_checker, probe_func, saved_findings=None):
    original_scope = workflow_module.check_scope
    original_probe = workflow_module.http_probe
    original_save = workflow_module.save_finding
    original_log = workflow_module.log_event
    original_classifier = workflow_module.classify_endpoint

    if saved_findings is None:
        saved_findings = []

    def fake_save(finding):
        saved_findings.append(finding)
        return {"saved": True, "path": "mock://findings"}

    workflow_module.check_scope = scope_checker
    workflow_module.http_probe = probe_func
    workflow_module.save_finding = fake_save
    workflow_module.log_event = lambda message: None
    workflow_module.classify_endpoint = lambda probe: {
        "classification": "frontend",
        "confidence": "high",
        "reason": "mock classifier",
    }

    return original_scope, original_probe, original_save, original_log, original_classifier, saved_findings


def restore_workflow(originals):
    original_scope, original_probe, original_save, original_log, original_classifier, _saved_findings = originals
    workflow_module.check_scope = original_scope
    workflow_module.http_probe = original_probe
    workflow_module.save_finding = original_save
    workflow_module.log_event = original_log
    workflow_module.classify_endpoint = original_classifier


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


def probe_response(url):
    return {
        "blocked": False,
        "status_code": 200,
        "final_url": "https://example.com/",
        "redirect_history": [],
        "title": "Example",
        "content_type": "text/html; charset=utf-8",
        "body_size": 123,
        "headers": {
            "content-type": "text/html; charset=utf-8",
            "content-length": "123",
            "set-cookie": "session=secret-cookie",
            "authorization": "Bearer secret-token",
            "x-api-token": "secret-token",
            "x-secret-value": "secret-value",
        },
        "text": "FULL_SECRET_RESPONSE_BODY",
    }


def test_out_of_scope_stops_without_requests():
    """Protects scope-first behavior and zero requests for out-of-scope targets."""
    calls = []

    def fake_probe(url):
        calls.append(url)
        return probe_response(url)

    originals = patch_workflow(out_of_scope, fake_probe)
    try:
        result = safe_http_probe_workflow("evil.test")

        assert_true(result["stopped"] is True, "Out-of-scope target should stop")
        assert_true(result["safety"]["requests_sent"] == 0, "Out-of-scope target should send 0 requests")
        assert_true(calls == [], "HTTP helper should not be called out of scope")
    finally:
        restore_workflow(originals)


def test_in_scope_calls_http_probe_once():
    """Protects the one-request budget for in-scope HTTP probing."""
    calls = []

    def fake_probe(url):
        calls.append(url)
        return probe_response(url)

    originals = patch_workflow(in_scope, fake_probe)
    try:
        result = safe_http_probe_workflow("https://example.com")

        assert_true(calls == ["https://example.com"], "HTTP helper should be called exactly once")
        assert_true(result["safety"]["requests_sent"] == 1, "requests_sent should be 1")
        assert_true(result["summary"]["max_requests"] == 1, "Summary should expose max request budget")
    finally:
        restore_workflow(originals)


def test_http_probe_exception_becomes_request_error():
    """Protects fail-closed behavior when http_probe raises."""
    calls = []

    def raising_probe(url):
        calls.append(url)
        raise RuntimeError("simulated failure")

    originals = patch_workflow(in_scope, raising_probe)
    try:
        result = safe_http_probe_workflow("https://example.com")
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true(result["stopped"] is False, "Workflow should not crash on helper exception")
        assert_true("request_error" in statuses, "Exception should become request_error observation")
        assert_true(result["safety"]["requests_sent"] == 1, "Attempted probe should count as one request")
        assert_true(calls == ["https://example.com"], "Exception path should still call helper once")
    finally:
        restore_workflow(originals)


def test_http_probe_non_dict_becomes_request_error():
    """Protects fail-closed behavior when http_probe returns malformed data."""
    calls = []

    def malformed_probe(url):
        calls.append(url)
        return "not a dict"

    originals = patch_workflow(in_scope, malformed_probe)
    try:
        result = safe_http_probe_workflow("https://example.com")
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true(result["stopped"] is False, "Workflow should not crash on non-dict helper output")
        assert_true("request_error" in statuses, "Non-dict result should become request_error observation")
        assert_true(result["safety"]["requests_sent"] == 1, "Malformed helper call should count once")
        assert_true(calls == ["https://example.com"], "Malformed path should still call helper once")
    finally:
        restore_workflow(originals)


def test_safety_metadata_is_low_risk_and_non_destructive():
    """Protects required safety flags for the low-risk single-probe workflow."""
    originals = patch_workflow(in_scope, probe_response)
    try:
        result = safe_http_probe_workflow("https://example.com")
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
    """Protects header minimization in result observations and probe summary."""
    saved_findings = []
    originals = patch_workflow(in_scope, probe_response, saved_findings=saved_findings)
    try:
        result = safe_http_probe_workflow("https://example.com")
        result_text = f"{result} {saved_findings}".lower()

        assert_true("content-type" in result_text, "Safe content-type metadata may be retained")
        assert_true("set-cookie" not in result_text, "Set-Cookie header must not be retained")
        assert_true("authorization" not in result_text, "Authorization header must not be retained")
        assert_true("secret-token" not in result_text, "Token-like header values must not be retained")
        assert_true("secret-value" not in result_text, "Secret-like header values must not be retained")
    finally:
        restore_workflow(originals)


def test_full_response_body_is_not_preserved():
    """Protects against storing full response bodies in result or saved finding."""
    saved_findings = []
    originals = patch_workflow(in_scope, probe_response, saved_findings=saved_findings)
    try:
        result = safe_http_probe_workflow("https://example.com")
        combined_output = f"{result} {saved_findings}"

        assert_true("FULL_SECRET_RESPONSE_BODY" not in combined_output, "Full response body must not be stored")
        assert_true(saved_findings, "Legacy observation saving should still occur")
    finally:
        restore_workflow(originals)


if __name__ == "__main__":
    test_out_of_scope_stops_without_requests()
    test_in_scope_calls_http_probe_once()
    test_http_probe_exception_becomes_request_error()
    test_http_probe_non_dict_becomes_request_error()
    test_safety_metadata_is_low_risk_and_non_destructive()
    test_sensitive_headers_are_not_preserved()
    test_full_response_body_is_not_preserved()

    print("All safe HTTP probe workflow tests passed.")
