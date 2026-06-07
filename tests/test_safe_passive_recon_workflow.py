import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from workflows import safe_passive_recon_workflow as workflow_module
from workflows.safe_passive_recon_workflow import safe_passive_recon_workflow


def assert_true(condition, message):
    """
    Assert passive recon workflow behavior without real network traffic.

    Tests patch scope checks, all child workflows, finding storage, priority
    scoring, and logging. The child workflows are represented by local mock
    dictionaries so no test sends an external request.
    """
    if not condition:
        raise AssertionError(message)


def patch_workflow(scope_checker, http_workflow, headers_workflow, cors_workflow, saved_findings=None):
    original_scope = workflow_module.check_scope
    original_http = workflow_module.safe_http_probe_workflow
    original_headers = workflow_module.safe_security_headers_workflow
    original_cors = workflow_module.safe_cors_observation_workflow
    original_save = workflow_module.save_finding
    original_log = workflow_module.log_event
    original_scorer = workflow_module.score_workflow_priority

    if saved_findings is None:
        saved_findings = []

    def fake_save(finding):
        saved_findings.append(finding)
        return {"saved": True, "path": "mock://findings"}

    workflow_module.check_scope = scope_checker
    workflow_module.safe_http_probe_workflow = http_workflow
    workflow_module.safe_security_headers_workflow = headers_workflow
    workflow_module.safe_cors_observation_workflow = cors_workflow
    workflow_module.save_finding = fake_save
    workflow_module.log_event = lambda message: None
    workflow_module.score_workflow_priority = lambda **kwargs: {
        "priority": "medium",
        "score": 40,
        "reasons": ["mock priority"],
    }

    return (
        original_scope,
        original_http,
        original_headers,
        original_cors,
        original_save,
        original_log,
        original_scorer,
        saved_findings,
    )


def restore_workflow(originals):
    (
        original_scope,
        original_http,
        original_headers,
        original_cors,
        original_save,
        original_log,
        original_scorer,
        _saved_findings,
    ) = originals
    workflow_module.check_scope = original_scope
    workflow_module.safe_http_probe_workflow = original_http
    workflow_module.safe_security_headers_workflow = original_headers
    workflow_module.safe_cors_observation_workflow = original_cors
    workflow_module.save_finding = original_save
    workflow_module.log_event = original_log
    workflow_module.score_workflow_priority = original_scorer


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


def http_child_result(target):
    return {
        "target": target,
        "stopped": False,
        "endpoint_classification": {
            "classification": "frontend",
            "confidence": "high",
            "reason": "mock classifier",
        },
        "probe_summary": {
            "status_code": 200,
            "final_url": "https://example.com/",
            "title": "Example",
            "content_type": "text/html; charset=utf-8",
            "body_size": 123,
            "headers": {
                "content-type": "text/html; charset=utf-8",
                "set-cookie": "session=secret-cookie",
                "authorization": "Bearer secret-token",
            },
            "body": "FULL_SECRET_RESPONSE_BODY",
        },
        "validator_result": {"status": "observation"},
        "safety": {"requests_sent": 1},
    }


def headers_child_result(target):
    return {
        "target": target,
        "stopped": False,
        "header_summary": {
            "status_code": 200,
            "url": "https://example.com/",
            "missing_headers": ["content-security-policy", "x-frame-options", "set-cookie"],
            "present_headers": {
                "strict-transport-security": "max-age=31536000",
                "set-cookie": "session=secret-cookie",
                "authorization": "Bearer secret-token",
                "x-api-token": "secret-token",
            },
            "missing_count": 3,
            "body": "FULL_SECRET_RESPONSE_BODY",
        },
        "validator_result": {
            "status": "candidate_finding",
            "severity": "low",
            "confidence": "medium",
            "should_report": False,
            "reason": "mock validator",
            "false_positive_notes": [],
        },
        "safety": {"requests_sent": 1},
    }


def cors_child_result(target):
    return {
        "target": target,
        "stopped": False,
        "cors_summary": {
            "status_code": 200,
            "final_url": "https://example.com/",
            "origin_tested": "https://example-attacker.invalid",
            "origin_reflected": True,
            "cors_headers": {
                "access-control-allow-origin": "https://example-attacker.invalid",
                "access-control-allow-credentials": "true",
                "access-control-allow-headers": "authorization, x-api-token",
                "set-cookie": "session=secret-cookie",
            },
            "body": "FULL_SECRET_RESPONSE_BODY",
        },
        "validator_result": {
            "status": "candidate_finding",
            "severity": "low",
            "confidence": "medium",
            "should_report": False,
            "reason": "mock validator",
            "false_positive_notes": [],
        },
        "safety": {"requests_sent": 1},
    }


def test_out_of_scope_stops_without_child_workflows():
    """Protects scope-first behavior and zero child workflow requests."""
    calls = []

    def fake_child(target):
        calls.append(target)
        return http_child_result(target)

    originals = patch_workflow(out_of_scope, fake_child, fake_child, fake_child)
    try:
        result = safe_passive_recon_workflow("evil.test")

        assert_true(result["stopped"] is True, "Out-of-scope target should stop")
        assert_true(result["safety"]["requests_sent"] == 0, "Out-of-scope target should report 0 requests")
        assert_true(calls == [], "Child workflows should not run out of scope")
    finally:
        restore_workflow(originals)


def test_in_scope_calls_existing_child_workflows():
    """Protects that passive recon still delegates to the original three child workflows."""
    calls = []

    def fake_http(target):
        calls.append("http")
        return http_child_result(target)

    def fake_headers(target):
        calls.append("headers")
        return headers_child_result(target)

    def fake_cors(target):
        calls.append("cors")
        return cors_child_result(target)

    originals = patch_workflow(in_scope, fake_http, fake_headers, fake_cors)
    try:
        result = safe_passive_recon_workflow("https://example.com")

        assert_true(calls == ["http", "headers", "cors"], "Child workflows should run once in order")
        assert_true(result["safety"]["requests_sent"] == 3, "Passive recon request budget should remain 3")
        assert_true(result["workflow_status"]["http_probe"] == "completed", "HTTP child should complete")
        assert_true(result["workflow_status"]["security_headers"] == "completed", "Headers child should complete")
        assert_true(result["workflow_status"]["cors_observation"] == "completed", "CORS child should complete")
    finally:
        restore_workflow(originals)


def test_child_workflow_exception_does_not_crash():
    """Protects fail-closed behavior when a child workflow raises an exception."""
    calls = []

    def fake_http(target):
        calls.append("http")
        return http_child_result(target)

    def raising_headers(target):
        calls.append("headers")
        raise RuntimeError("simulated child failure")

    def fake_cors(target):
        calls.append("cors")
        return cors_child_result(target)

    originals = patch_workflow(in_scope, fake_http, raising_headers, fake_cors)
    try:
        result = safe_passive_recon_workflow("https://example.com")
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true(result["stopped"] is False, "Workflow should not crash on child exception")
        assert_true("error" in result["workflow_status"].values(), "Child exception should affect workflow status")
        assert_true(result.get("errors"), "Child exception should be recorded in errors")
        assert_true("error" in statuses, "Parent observations should record child error status")
        assert_true(calls == ["http", "headers", "cors"], "Other child workflows should still be called")
    finally:
        restore_workflow(originals)


def test_child_workflow_non_dict_does_not_crash():
    """Protects fail-closed behavior when a child workflow returns malformed output."""
    calls = []

    def fake_http(target):
        calls.append("http")
        return http_child_result(target)

    def malformed_headers(target):
        calls.append("headers")
        return "not a dict"

    def fake_cors(target):
        calls.append("cors")
        return cors_child_result(target)

    originals = patch_workflow(in_scope, fake_http, malformed_headers, fake_cors)
    try:
        result = safe_passive_recon_workflow("https://example.com")

        assert_true(result["stopped"] is False, "Workflow should not crash on non-dict child result")
        assert_true(result["workflow_status"]["security_headers"] == "error", "Malformed child should be error")
        assert_true(result.get("errors"), "Malformed child result should be recorded")
        assert_true(calls == ["http", "headers", "cors"], "Malformed child should not stop remaining child workflows")
    finally:
        restore_workflow(originals)


def test_safety_metadata_is_low_risk_and_non_destructive():
    """Protects passive recon safety metadata and original request budget."""
    originals = patch_workflow(in_scope, http_child_result, headers_child_result, cors_child_result)
    try:
        result = safe_passive_recon_workflow("https://example.com")
        safety = result.get("safety", {})

        assert_true(safety["scan_level"] == "low-risk", "Passive recon should remain low-risk")
        assert_true(safety["requests_sent"] <= 3, "Passive recon must not exceed the original request budget")
        assert_true(safety["fuzzing"] is False, "Workflow should not fuzz")
        assert_true(safety["bruteforce"] is False, "Workflow should not brute force")
        assert_true(safety["exploitation"] is False, "Workflow should not exploit")
        assert_true(safety["crawling"] is False, "Workflow should not crawl")
        assert_true(safety["credentialed_request"] is False, "Workflow should not use credentials")
        assert_true(safety["state_changing"] is False, "Workflow should not change target state")
    finally:
        restore_workflow(originals)


def test_sensitive_headers_are_not_preserved():
    """Protects minimization of sensitive child workflow metadata before storage."""
    saved_findings = []
    originals = patch_workflow(
        in_scope,
        http_child_result,
        headers_child_result,
        cors_child_result,
        saved_findings=saved_findings,
    )
    try:
        result = safe_passive_recon_workflow("https://example.com")
        result_text = f"{result} {saved_findings}".lower()

        assert_true("content-security-policy" in result_text, "Safe header metadata may be retained")
        assert_true("access-control-allow-origin" in result_text, "Safe CORS metadata may be retained")
        assert_true("set-cookie" not in result_text, "Set-Cookie header must not be retained")
        assert_true("authorization" not in result_text, "Authorization header must not be retained")
        assert_true("secret-token" not in result_text, "Token-like values must not be retained")
    finally:
        restore_workflow(originals)


def test_full_response_body_is_not_preserved():
    """Protects against storing full response bodies in result or saved finding."""
    saved_findings = []
    originals = patch_workflow(
        in_scope,
        http_child_result,
        headers_child_result,
        cors_child_result,
        saved_findings=saved_findings,
    )
    try:
        result = safe_passive_recon_workflow("https://example.com")
        combined_output = f"{result} {saved_findings}"

        assert_true("FULL_SECRET_RESPONSE_BODY" not in combined_output, "Full response body must not be stored")
        assert_true(saved_findings, "Legacy summary save behavior should be preserved")
    finally:
        restore_workflow(originals)


if __name__ == "__main__":
    test_out_of_scope_stops_without_child_workflows()
    test_in_scope_calls_existing_child_workflows()
    test_child_workflow_exception_does_not_crash()
    test_child_workflow_non_dict_does_not_crash()
    test_safety_metadata_is_low_risk_and_non_destructive()
    test_sensitive_headers_are_not_preserved()
    test_full_response_body_is_not_preserved()

    print("All safe passive recon workflow tests passed.")
