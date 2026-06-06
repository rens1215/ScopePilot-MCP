import sys
from pathlib import Path
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from workflows import safe_robots_securitytxt_workflow as workflow_module
from workflows.safe_robots_securitytxt_workflow import safe_robots_securitytxt_workflow


ALLOWED_PATHS = {
    "/robots.txt",
    "/.well-known/security.txt",
    "/sitemap.xml",
}


def assert_true(condition, message):
    """
    Assert workflow safety test conditions without external dependencies.

    Tests patch HTTP probing and scope checks, so they never send real network
    requests and only verify workflow control flow and returned metadata.
    """
    if not condition:
        raise AssertionError(message)


def patch_workflow(scope_result, probe_func):
    original_scope = workflow_module.check_scope
    original_probe = workflow_module.http_probe
    original_log = workflow_module.log_event

    workflow_module.check_scope = lambda target: scope_result
    workflow_module.http_probe = probe_func
    workflow_module.log_event = lambda message: None

    return original_scope, original_probe, original_log


def restore_workflow(originals):
    original_scope, original_probe, original_log = originals
    workflow_module.check_scope = original_scope
    workflow_module.http_probe = original_probe
    workflow_module.log_event = original_log


def in_scope(target="example.com"):
    return {
        "target": target,
        "hostname": "example.com",
        "in_scope": True,
        "reason": "test scope",
        "allowed_scan_level": "passive_or_light",
    }


def out_of_scope(target="evil.test"):
    return {
        "target": target,
        "hostname": "evil.test",
        "in_scope": False,
        "reason": "test out of scope",
        "allowed_scan_level": "forbidden",
    }


def make_probe(calls, robots_body="User-agent: *\nDisallow: /admin\n"):
    def fake_probe(url):
        calls.append(url)
        path = urlsplit(url).path
        if path == "/robots.txt":
            body_size = len(robots_body.encode("utf-8"))
            return {
                "blocked": False,
                "status_code": 200,
                "final_url": url,
                "headers": {"content-type": "text/plain", "set-cookie": "secret=bad"},
                "content_type": "text/plain",
                "body_size": body_size,
            }
        if path == "/.well-known/security.txt":
            return {
                "blocked": False,
                "status_code": 404,
                "final_url": url,
                "headers": {"content-type": "text/plain"},
                "content_type": "text/plain",
                "body_size": 0,
            }
        if path == "/sitemap.xml":
            return {
                "blocked": False,
                "status_code": 200,
                "final_url": url,
                "headers": {"content-type": "application/xml"},
                "content_type": "application/xml",
                "body_size": 128,
            }

        raise AssertionError(f"Unexpected path requested: {path}")

    return fake_probe


def test_out_of_scope_stops_without_requests():
    """Protects scope-first behavior and zero requests for out-of-scope targets."""
    calls = []
    originals = patch_workflow(out_of_scope(), make_probe(calls))
    try:
        result = safe_robots_securitytxt_workflow("evil.test")

        assert_true(result["stopped"] is True, "Out-of-scope target should stop")
        assert_true(result["safety"]["requests_sent"] == 0, "Out-of-scope target should send 0 requests")
        assert_true(calls == [], "HTTP probe should not be called out of scope")
    finally:
        restore_workflow(originals)


def test_in_scope_requests_at_most_three_metadata_paths():
    """Protects the strict three-request metadata limit."""
    calls = []
    originals = patch_workflow(in_scope(), make_probe(calls))
    try:
        result = safe_robots_securitytxt_workflow("example.com")

        assert_true(result["safety"]["requests_sent"] == 3, "Workflow should report exactly 3 metadata requests")
        assert_true(len(calls) == 3, "Workflow should call HTTP helper exactly 3 times")
    finally:
        restore_workflow(originals)


def test_only_allowed_metadata_paths_are_requested():
    """Protects the fixed allowlist of public metadata paths."""
    calls = []
    originals = patch_workflow(in_scope(), make_probe(calls))
    try:
        result = safe_robots_securitytxt_workflow("example.com")
        requested_paths = {urlsplit(url).path for url in calls}

        assert_true(requested_paths == ALLOWED_PATHS, "Workflow should only request allowed metadata paths")
        assert_true(set(result["allowed_metadata_paths"]) == ALLOWED_PATHS, "Result should disclose allowed paths")
    finally:
        restore_workflow(originals)


def test_robots_disallow_paths_are_not_requested():
    """Protects against treating robots.txt Disallow paths as scan authorization."""
    calls = []
    originals = patch_workflow(in_scope(), make_probe(calls, robots_body="User-agent: *\nDisallow: /admin\n"))
    try:
        safe_robots_securitytxt_workflow("example.com")
        requested_paths = {urlsplit(url).path for url in calls}

        assert_true("/admin" not in requested_paths, "Workflow must not request robots.txt Disallow paths")
    finally:
        restore_workflow(originals)


def test_returns_safety_metadata():
    """Protects required safety metadata for the low-risk workflow."""
    calls = []
    originals = patch_workflow(in_scope(), make_probe(calls))
    try:
        result = safe_robots_securitytxt_workflow("example.com")
        safety = result.get("safety", {})

        assert_true(safety["scan_level"] == "low-risk", "Workflow should be low-risk")
        assert_true(safety["fuzzing"] is False, "Workflow should not fuzz")
        assert_true(safety["bruteforce"] is False, "Workflow should not brute force")
        assert_true(safety["exploitation"] is False, "Workflow should not exploit")
        assert_true(safety["crawling"] is False, "Workflow should not crawl")
        assert_true(safety["credentialed_request"] is False, "Workflow should not use credentials")
    finally:
        restore_workflow(originals)


def test_produces_inventory_candidate_items():
    """Protects conversion of metadata observations into safe inventory candidates."""
    calls = []
    originals = patch_workflow(in_scope(), make_probe(calls))
    try:
        result = safe_robots_securitytxt_workflow("example.com")
        candidates = result.get("inventory_candidates", [])

        assert_true(len(candidates) == 3, "Workflow should produce one candidate per metadata path")
        for candidate in candidates:
            assert_true(candidate["target"] == "example.com", "Candidate should preserve target")
            assert_true(candidate["normalized_url"].startswith("https://example.com/"), "Candidate should include normalized URL")
            assert_true(candidate["source"] in {"robots", "security_txt", "sitemap"}, "Candidate source should be metadata source")
            assert_true("set-cookie" not in candidate["evidence"]["headers_summary"], "Sensitive headers should not be saved")
    finally:
        restore_workflow(originals)


def test_http_probe_exception_becomes_request_error():
    """Protects workflow stability when the HTTP helper raises an exception."""
    calls = []

    def raising_probe(url):
        calls.append(url)
        raise RuntimeError("simulated probe failure")

    originals = patch_workflow(in_scope(), raising_probe)
    try:
        result = safe_robots_securitytxt_workflow("example.com")
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true(result["stopped"] is False, "Workflow should not crash or stop after probe exceptions")
        assert_true("request_error" in statuses, "Probe exception should produce request_error observation")
        assert_true("safety" in result, "Safety metadata should still be returned")
        assert_true(result["safety"]["requests_sent"] == 3, "Attempted helper calls should count against request limit")
        assert_true(len(calls) == 3, "Workflow should still only attempt the three metadata paths")
    finally:
        restore_workflow(originals)


def test_http_probe_non_dict_result_becomes_request_error():
    """Protects workflow stability when the HTTP helper returns malformed data."""
    calls = []

    def malformed_probe(url):
        calls.append(url)
        return "not a dict"

    originals = patch_workflow(in_scope(), malformed_probe)
    try:
        result = safe_robots_securitytxt_workflow("example.com")
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true(result["stopped"] is False, "Workflow should not crash on non-dict probe result")
        assert_true("request_error" in statuses, "Non-dict probe result should produce request_error observation")
        assert_true("safety" in result, "Safety metadata should still be returned")
        assert_true(result["safety"]["requests_sent"] == 3, "Malformed helper calls should count against request limit")
        assert_true(len(calls) == 3, "Workflow should still only attempt the three metadata paths")
    finally:
        restore_workflow(originals)


if __name__ == "__main__":
    test_out_of_scope_stops_without_requests()
    test_in_scope_requests_at_most_three_metadata_paths()
    test_only_allowed_metadata_paths_are_requested()
    test_robots_disallow_paths_are_not_requested()
    test_returns_safety_metadata()
    test_produces_inventory_candidate_items()
    test_http_probe_exception_becomes_request_error()
    test_http_probe_non_dict_result_becomes_request_error()

    print("All robots/security.txt workflow tests passed.")
