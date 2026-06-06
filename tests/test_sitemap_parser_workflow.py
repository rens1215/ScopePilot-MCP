import sys
from pathlib import Path
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from workflows import safe_sitemap_parser_workflow as workflow_module
from workflows.safe_sitemap_parser_workflow import safe_sitemap_parser_workflow


def assert_true(condition, message):
    """
    Assert sitemap workflow safety behavior without external dependencies.

    These tests patch scope checks and HTTP probing, so they never send real
    network requests. They only verify workflow limits, parsing behavior, and
    inventory candidate construction.
    """
    if not condition:
        raise AssertionError(message)


def patch_workflow(scope_checker, probe_func):
    original_scope = workflow_module.check_scope
    original_probe = workflow_module.http_probe
    original_log = workflow_module.log_event

    workflow_module.check_scope = scope_checker
    workflow_module.http_probe = probe_func
    workflow_module.log_event = lambda message: None

    return original_scope, original_probe, original_log


def restore_workflow(originals):
    original_scope, original_probe, original_log = originals
    workflow_module.check_scope = original_scope
    workflow_module.http_probe = original_probe
    workflow_module.log_event = original_log


def in_scope_result(target="example.com"):
    return {
        "target": target,
        "hostname": "example.com",
        "in_scope": True,
        "reason": "test scope",
        "allowed_scan_level": "passive_or_light",
    }


def out_of_scope_result(target="evil.test"):
    return {
        "target": target,
        "hostname": "evil.test",
        "in_scope": False,
        "reason": "test out of scope",
        "allowed_scan_level": "forbidden",
    }


def scope_checker_for_example(target):
    parsed_hostname = (urlsplit(target if "://" in target else f"https://{target}").hostname or "").lower()
    if parsed_hostname == "example.com":
        return in_scope_result(target)
    return out_of_scope_result(target)


def make_sitemap(urls):
    locs = "".join(f"<url><loc>{url}</loc></url>" for url in urls)
    return f'<?xml version="1.0" encoding="UTF-8"?><urlset>{locs}</urlset>'


def make_probe(calls, text=None, status_code=200, body_size=None):
    if text is None:
        text = make_sitemap(["https://example.com/login", "https://example.com/api/users"])

    def fake_probe(url):
        calls.append(url)
        path = urlsplit(url).path
        if path != "/sitemap.xml":
            raise AssertionError(f"Unexpected path requested: {path}")

        encoded_size = len(text.encode("utf-8"))
        return {
            "blocked": False,
            "status_code": status_code,
            "final_url": url,
            "headers": {"content-type": "application/xml", "set-cookie": "secret=bad"},
            "content_type": "application/xml",
            "body_size": encoded_size if body_size is None else body_size,
            "text": text,
        }

    return fake_probe


def test_out_of_scope_stops_without_requests():
    """Protects scope-first behavior and zero requests for out-of-scope targets."""
    calls = []
    originals = patch_workflow(lambda target: out_of_scope_result(target), make_probe(calls))
    try:
        result = safe_sitemap_parser_workflow("evil.test")

        assert_true(result["stopped"] is True, "Out-of-scope target should stop")
        assert_true(result["safety"]["requests_sent"] == 0, "Out-of-scope target should send 0 requests")
        assert_true(calls == [], "HTTP probe should not be called out of scope")
    finally:
        restore_workflow(originals)


def test_in_scope_requests_only_sitemap_xml():
    """Protects the single fixed /sitemap.xml request path."""
    calls = []
    originals = patch_workflow(scope_checker_for_example, make_probe(calls))
    try:
        result = safe_sitemap_parser_workflow("example.com")
        requested_paths = [urlsplit(url).path for url in calls]

        assert_true(result["safety"]["requests_sent"] == 1, "Workflow should report one request")
        assert_true(requested_paths == ["/sitemap.xml"], "Workflow should only request /sitemap.xml")
        assert_true(result["allowed_sitemap_path"] == "/sitemap.xml", "Result should disclose allowed path")
    finally:
        restore_workflow(originals)


def test_does_not_request_urls_listed_in_sitemap():
    """Protects against turning sitemap entries into automatic crawl targets."""
    calls = []
    sitemap = make_sitemap(["https://example.com/login", "https://example.com/api/users"])
    originals = patch_workflow(scope_checker_for_example, make_probe(calls, text=sitemap))
    try:
        safe_sitemap_parser_workflow("example.com")
        requested_urls = set(calls)

        assert_true(len(requested_urls) == 1, "Workflow should make exactly one HTTP helper call")
        assert_true("https://example.com/login" not in requested_urls, "Extracted URLs must not be requested")
        assert_true("https://example.com/api/users" not in requested_urls, "Extracted API URLs must not be requested")
    finally:
        restore_workflow(originals)


def test_extracts_candidates_from_valid_sitemap_xml():
    """Protects conversion of valid sitemap URLs into safe inventory candidates."""
    calls = []
    sitemap = make_sitemap(["https://example.com/login", "https://example.com/api/users"])
    originals = patch_workflow(scope_checker_for_example, make_probe(calls, text=sitemap))
    try:
        result = safe_sitemap_parser_workflow("example.com")
        candidates = result.get("inventory_candidates", [])
        normalized_urls = {candidate["normalized_url"] for candidate in candidates}

        assert_true(len(candidates) == 2, "Workflow should build candidates for sitemap URLs")
        assert_true("https://example.com/login" in normalized_urls, "Login URL should be a candidate")
        assert_true("https://example.com/api/users" in normalized_urls, "API URL should be a candidate")
        for candidate in candidates:
            assert_true(candidate["source"] == "sitemap", "Candidate source should be sitemap")
            assert_true("set-cookie" not in candidate["evidence"]["headers_summary"], "Sensitive headers should not be saved")
    finally:
        restore_workflow(originals)


def test_max_urls_limit_is_enforced():
    """Protects request-budget-adjacent URL extraction limits."""
    calls = []
    sitemap = make_sitemap(
        [
            "https://example.com/one",
            "https://example.com/two",
            "https://example.com/three",
        ]
    )
    originals = patch_workflow(scope_checker_for_example, make_probe(calls, text=sitemap))
    try:
        result = safe_sitemap_parser_workflow("example.com", max_urls=2)

        assert_true(len(result["inventory_candidates"]) == 2, "Workflow should honor max_urls")
        assert_true(result["summary"]["extracted_url_count"] == 2, "Summary should reflect max_urls")
    finally:
        restore_workflow(originals)


def test_oversized_sitemap_is_rejected_without_parsing():
    """Protects max_sitemap_bytes so large XML bodies are not processed."""
    calls = []
    sitemap = make_sitemap(["https://example.com/login"])
    originals = patch_workflow(scope_checker_for_example, make_probe(calls, text=sitemap, body_size=9999))
    try:
        result = safe_sitemap_parser_workflow("example.com", max_sitemap_bytes=10)
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true("oversized" in statuses, "Oversized sitemap should be rejected")
        assert_true(result["inventory_candidates"] == [], "Oversized sitemap should not create candidates")
    finally:
        restore_workflow(originals)


def test_invalid_xml_becomes_parse_error():
    """Protects workflow stability when sitemap XML is malformed."""
    calls = []
    originals = patch_workflow(scope_checker_for_example, make_probe(calls, text="<urlset><url>"))
    try:
        result = safe_sitemap_parser_workflow("example.com")
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true("parse_error" in statuses, "Invalid XML should produce parse_error")
        assert_true(result["inventory_candidates"] == [], "Invalid XML should not create candidates")
    finally:
        restore_workflow(originals)


def test_http_probe_exception_becomes_request_error():
    """Protects workflow stability when the HTTP helper raises an exception."""
    calls = []

    def raising_probe(url):
        calls.append(url)
        raise RuntimeError("simulated probe failure")

    originals = patch_workflow(scope_checker_for_example, raising_probe)
    try:
        result = safe_sitemap_parser_workflow("example.com")
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true(result["stopped"] is False, "Workflow should not crash after helper exception")
        assert_true("request_error" in statuses, "Probe exception should produce request_error")
        assert_true("safety" in result, "Safety metadata should still be returned")
        assert_true(result["safety"]["requests_sent"] == 1, "Attempted helper call should count against limit")
    finally:
        restore_workflow(originals)


def test_http_probe_non_dict_result_becomes_request_error():
    """Protects workflow stability when the HTTP helper returns malformed data."""
    calls = []

    def malformed_probe(url):
        calls.append(url)
        return "not a dict"

    originals = patch_workflow(scope_checker_for_example, malformed_probe)
    try:
        result = safe_sitemap_parser_workflow("example.com")
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true(result["stopped"] is False, "Workflow should not crash on non-dict probe result")
        assert_true("request_error" in statuses, "Non-dict probe result should produce request_error")
        assert_true("safety" in result, "Safety metadata should still be returned")
        assert_true(result["safety"]["requests_sent"] == 1, "Malformed helper call should count against limit")
    finally:
        restore_workflow(originals)


def test_out_of_scope_urls_are_not_inventory_candidates():
    """Protects scope filtering for URLs extracted from sitemap XML."""
    calls = []
    sitemap = make_sitemap(
        [
            "https://example.com/login",
            "https://evil.test/admin",
        ]
    )
    originals = patch_workflow(scope_checker_for_example, make_probe(calls, text=sitemap))
    try:
        result = safe_sitemap_parser_workflow("example.com")
        normalized_urls = {candidate["normalized_url"] for candidate in result.get("inventory_candidates", [])}
        skipped_urls = result.get("skipped_urls", [])

        assert_true("https://example.com/login" in normalized_urls, "Same-host URL should be kept")
        assert_true("https://evil.test/admin" not in normalized_urls, "Out-of-scope URL should not be a candidate")
        assert_true(len(skipped_urls) == 1, "Out-of-scope URL should be recorded as skipped")
    finally:
        restore_workflow(originals)


def test_returns_safety_metadata():
    """Protects required safety flags for low-risk sitemap parsing."""
    calls = []
    originals = patch_workflow(scope_checker_for_example, make_probe(calls))
    try:
        result = safe_sitemap_parser_workflow("example.com")
        safety = result.get("safety", {})

        assert_true(safety["scan_level"] == "low-risk", "Workflow should be low-risk")
        assert_true(safety["requests_sent"] == 1, "Workflow should send at most one request")
        assert_true(safety["fuzzing"] is False, "Workflow should not fuzz")
        assert_true(safety["bruteforce"] is False, "Workflow should not brute force")
        assert_true(safety["exploitation"] is False, "Workflow should not exploit")
        assert_true(safety["crawling"] is False, "Workflow should not crawl")
        assert_true(safety["credentialed_request"] is False, "Workflow should not use credentials")
    finally:
        restore_workflow(originals)


if __name__ == "__main__":
    test_out_of_scope_stops_without_requests()
    test_in_scope_requests_only_sitemap_xml()
    test_does_not_request_urls_listed_in_sitemap()
    test_extracts_candidates_from_valid_sitemap_xml()
    test_max_urls_limit_is_enforced()
    test_oversized_sitemap_is_rejected_without_parsing()
    test_invalid_xml_becomes_parse_error()
    test_http_probe_exception_becomes_request_error()
    test_http_probe_non_dict_result_becomes_request_error()
    test_out_of_scope_urls_are_not_inventory_candidates()
    test_returns_safety_metadata()

    print("All sitemap parser workflow tests passed.")
