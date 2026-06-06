import sys
from pathlib import Path
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from workflows import safe_js_endpoint_extraction_workflow as workflow_module
from workflows.safe_js_endpoint_extraction_workflow import safe_js_endpoint_extraction_workflow


def assert_true(condition, message):
    """
    Assert JS endpoint extraction workflow behavior without real network use.

    Tests patch scope checks, HTTP probing, and logging. Any unexpected request
    URL in a mock probe raises, so the tests protect the no-crawl and
    do-not-request-extracted-endpoints boundaries.
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


def scope_result(target, hostname="example.com", in_scope=True):
    return {
        "target": target,
        "hostname": hostname,
        "in_scope": in_scope,
        "reason": "test scope" if in_scope else "test out of scope",
        "allowed_scan_level": "passive_or_light" if in_scope else "forbidden",
    }


def scope_checker(target):
    candidate = target if "://" in target else f"https://{target}"
    hostname = (urlsplit(candidate).hostname or "").lower()
    if hostname in {"example.com", "assets.example.com"}:
        return scope_result(target, hostname=hostname, in_scope=True)
    return scope_result(target, hostname=hostname, in_scope=False)


def html_with_scripts(script_srcs):
    tags = "".join(f'<script src="{src}"></script>' for src in script_srcs)
    return f"<html><head>{tags}</head><body>ok</body></html>"


def probe_response(url, text, content_type):
    return {
        "blocked": False,
        "status_code": 200,
        "final_url": url,
        "headers": {"content-type": content_type, "set-cookie": "secret=bad"},
        "content_type": content_type,
        "body_size": len(text.encode("utf-8")),
        "text": text,
    }


def make_probe(
    calls,
    html_text,
    js_by_path,
    html_content_type="text/html",
    js_content_type="application/javascript",
    js_content_type_by_path=None,
):
    if js_content_type_by_path is None:
        js_content_type_by_path = {}

    def fake_probe(url):
        calls.append(url)
        parsed = urlsplit(url)

        if parsed.hostname == "example.com" and parsed.path == "/":
            return probe_response(url, html_text, html_content_type)

        key = f"{parsed.hostname}{parsed.path}"
        if key in js_by_path:
            content_type = js_content_type_by_path.get(key, js_content_type)
            return probe_response(url, js_by_path[key], content_type)

        raise AssertionError(f"Unexpected request URL: {url}")

    return fake_probe


def test_out_of_scope_stops_without_requests():
    """Protects scope-first behavior and zero requests for out-of-scope targets."""
    calls = []
    originals = patch_workflow(lambda target: scope_result(target, hostname="evil.test", in_scope=False), make_probe(calls, "", {}))
    try:
        result = safe_js_endpoint_extraction_workflow("evil.test")

        assert_true(result["stopped"] is True, "Out-of-scope target should stop")
        assert_true(result["safety"]["requests_sent"] == 0, "Out-of-scope target should send 0 requests")
        assert_true(calls == [], "HTTP helper should not be called out of scope")
    finally:
        restore_workflow(originals)


def test_requests_target_html_and_limited_js_files_only():
    """Protects the 1 + max_js_files request boundary."""
    calls = []
    scripts = [f"/static/app{i}.js" for i in range(5)]
    html = html_with_scripts(scripts)
    js = {f"example.com/static/app{i}.js": "fetch('/api/users')" for i in range(5)}
    originals = patch_workflow(scope_checker, make_probe(calls, html, js))
    try:
        result = safe_js_endpoint_extraction_workflow("example.com", max_js_files=2)
        paths = [urlsplit(url).path for url in calls]

        assert_true(result["safety"]["requests_sent"] == 3, "Workflow should request HTML plus two JS files")
        assert_true(paths == ["/", "/static/app0.js", "/static/app1.js"], "Workflow should stop at max_js_files")
        assert_true(len(result["script_urls"]) == 2, "Result should include only fetched JS URLs")
    finally:
        restore_workflow(originals)


def test_max_js_files_hard_cap_limits_requests_to_31():
    """Protects the hard cap: 1 HTML request plus at most 30 JS requests."""
    calls = []
    scripts = [f"/static/app{i}.js" for i in range(35)]
    html = html_with_scripts(scripts)
    js = {f"example.com/static/app{i}.js": "fetch('/api/users')" for i in range(35)}
    originals = patch_workflow(scope_checker, make_probe(calls, html, js))
    try:
        result = safe_js_endpoint_extraction_workflow("example.com", max_js_files=100)
        summary = result["summary"]

        assert_true(len(calls) == 31, "Workflow should call HTTP helper at most 31 times")
        assert_true(result["safety"]["requests_sent"] == 31, "requests_sent must not exceed 31")
        assert_true(len(result["script_urls"]) == 30, "Workflow should fetch at most 30 JS files")
        assert_true(summary["requested_max_js_files"] == 100, "Summary should preserve requested max_js_files")
        assert_true(summary["effective_max_js_files"] == 30, "Summary should report effective hard-capped JS limit")
        assert_true(summary["hard_max_js_files"] == 30, "Summary should report hard JS limit")
        assert_true(summary["hard_max_total_requests"] == 31, "Summary should report hard request limit")
    finally:
        restore_workflow(originals)


def test_default_max_js_files_is_20():
    """Protects the larger default request budget for big frontend domains."""
    calls = []
    scripts = [f"/assets/app{i}.js" for i in range(25)]
    html = html_with_scripts(scripts)
    js = {f"example.com/assets/app{i}.js": "fetch('/api/users')" for i in range(25)}
    originals = patch_workflow(scope_checker, make_probe(calls, html, js))
    try:
        result = safe_js_endpoint_extraction_workflow("example.com")
        summary = result["summary"]

        assert_true(len(calls) == 21, "Default should request HTML plus 20 JS files")
        assert_true(summary["requested_max_js_files"] == 20, "Default requested max_js_files should be 20")
        assert_true(summary["effective_max_js_files"] == 20, "Default effective max_js_files should be 20")
        assert_true(summary["hard_max_js_files"] == 30, "Summary should include hard JS cap")
        assert_true(summary["hard_max_total_requests"] == 31, "Summary should include hard request cap")
    finally:
        restore_workflow(originals)


def test_only_same_host_or_in_scope_js_is_requested():
    """Protects filtering of cross-scope script src URLs before HTTP requests."""
    calls = []
    html = html_with_scripts(
        [
            "/static/app.js",
            "https://assets.example.com/bundle.js",
            "https://evil.test/evil.js",
        ]
    )
    js = {
        "example.com/static/app.js": "fetch('/api/local')",
        "assets.example.com/bundle.js": "fetch('/api/asset')",
    }
    originals = patch_workflow(scope_checker, make_probe(calls, html, js))
    try:
        result = safe_js_endpoint_extraction_workflow("example.com")
        requested_hosts = {urlsplit(url).hostname for url in calls}

        assert_true("evil.test" not in requested_hosts, "Out-of-scope JS host must not be requested")
        assert_true(len(result["script_urls"]) == 2, "Same-host and in-scope JS files should be allowed")
        assert_true(len(result["skipped_scripts"]) == 1, "Out-of-scope JS should be recorded as skipped")
    finally:
        restore_workflow(originals)


def test_html_json_content_type_is_not_parsed():
    """Protects HTML content-type gating before script src extraction."""
    calls = []
    html = html_with_scripts(["/static/app.js"])
    js = {"example.com/static/app.js": "fetch('/api/users')"}
    originals = patch_workflow(
        scope_checker,
        make_probe(calls, html, js, html_content_type="application/json"),
    )
    try:
        result = safe_js_endpoint_extraction_workflow("example.com")
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true(statuses == ["unsupported_content_type"], "JSON HTML response should not be parsed")
        assert_true(len(calls) == 1, "Workflow should not request JS when HTML type is unsupported")
        assert_true(result["script_urls"] == [], "No script URLs should be parsed from JSON")
    finally:
        restore_workflow(originals)


def test_js_json_content_type_is_not_parsed():
    """Protects JavaScript content-type gating before endpoint extraction."""
    calls = []
    html = html_with_scripts(["/static/app.js"])
    js = {"example.com/static/app.js": "fetch('/api/users')"}
    originals = patch_workflow(
        scope_checker,
        make_probe(
            calls,
            html,
            js,
            js_content_type_by_path={"example.com/static/app.js": "application/json"},
        ),
    )
    try:
        result = safe_js_endpoint_extraction_workflow("example.com")
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true("unsupported_content_type" in statuses, "JSON JS response should not be parsed")
        assert_true(result["endpoint_candidates"] == [], "Unsupported JS content type should yield no candidates")
        assert_true(result["inventory_candidates"] == [], "Unsupported JS content type should create no inventory")
    finally:
        restore_workflow(originals)


def test_extracted_api_endpoints_are_not_requested():
    """Protects against turning JS-discovered API strings into HTTP requests."""
    calls = []
    html = html_with_scripts(["/static/app.js"])
    js = {
        "example.com/static/app.js": "fetch('/api/users'); const v = 'https://example.com/v1/items';",
    }
    originals = patch_workflow(scope_checker, make_probe(calls, html, js))
    try:
        result = safe_js_endpoint_extraction_workflow("example.com")
        requested_paths = {urlsplit(url).path for url in calls}

        assert_true("/api/users" not in requested_paths, "Extracted API path must not be requested")
        assert_true("/v1/items" not in requested_paths, "Extracted absolute API URL must not be requested")
        assert_true(result["summary"]["endpoint_candidate_count"] == 2, "Endpoints should become candidates only")
    finally:
        restore_workflow(originals)


def test_max_js_files_zero_does_not_request_js():
    """Protects fail-safe handling for max_js_files <= 0."""
    calls = []
    html = html_with_scripts(["/static/app.js"])
    js = {"example.com/static/app.js": "fetch('/api/users')"}
    originals = patch_workflow(scope_checker, make_probe(calls, html, js))
    try:
        result = safe_js_endpoint_extraction_workflow("example.com", max_js_files=0)

        assert_true(result["safety"]["requests_sent"] == 1, "Only HTML should be requested")
        assert_true(result["script_urls"] == [], "No JS should be requested when effective limit is 0")
        assert_true(result["summary"]["effective_max_js_files"] == 0, "Summary should report 0 effective JS files")
    finally:
        restore_workflow(originals)


def test_max_js_files_limit_is_enforced():
    """Protects bounded JS file fetching when many scripts are present."""
    calls = []
    scripts = [f"/js/{index}.js" for index in range(4)]
    html = html_with_scripts(scripts)
    js = {f"example.com/js/{index}.js": "fetch('/api/users')" for index in range(4)}
    originals = patch_workflow(scope_checker, make_probe(calls, html, js))
    try:
        result = safe_js_endpoint_extraction_workflow("example.com", max_js_files=1)

        assert_true(result["safety"]["requests_sent"] == 2, "Only HTML plus one JS should be requested")
        assert_true(len(result["script_urls"]) == 1, "Only one JS URL should be fetched")
        assert_true(len(result["skipped_scripts"]) == 3, "Remaining scripts should be skipped")
    finally:
        restore_workflow(originals)


def test_max_js_bytes_zero_does_not_crash():
    """Protects fail-safe handling for max_js_bytes <= 0."""
    calls = []
    html = html_with_scripts(["/static/app.js"])
    js = {"example.com/static/app.js": "fetch('/api/users')"}
    originals = patch_workflow(scope_checker, make_probe(calls, html, js))
    try:
        result = safe_js_endpoint_extraction_workflow("example.com", max_js_bytes=0)
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true("skipped_oversized" in statuses, "Positive-size JS should be skipped when max_js_bytes is 0")
        assert_true(result["inventory_candidates"] == [], "No candidates should be created from skipped JS")
    finally:
        restore_workflow(originals)


def test_max_candidates_zero_does_not_crash():
    """Protects fail-safe handling for max_candidates <= 0."""
    calls = []
    html = html_with_scripts(["/static/app.js"])
    js = {"example.com/static/app.js": "fetch('/api/users')"}
    originals = patch_workflow(scope_checker, make_probe(calls, html, js))
    try:
        result = safe_js_endpoint_extraction_workflow("example.com", max_candidates=0)

        assert_true(result["endpoint_candidates"] == [], "No endpoint candidates should be extracted")
        assert_true(result["inventory_candidates"] == [], "No inventory candidates should be created")
        assert_true(result["summary"]["max_candidates"] == 0, "Summary should report 0 max candidates")
    finally:
        restore_workflow(originals)


def test_max_js_bytes_limit_is_enforced():
    """Protects size limits so oversized JavaScript is not parsed."""
    calls = []
    html = html_with_scripts(["/static/large.js"])
    js = {"example.com/static/large.js": "fetch('/api/users')"}

    def oversized_probe(url):
        calls.append(url)
        parsed = urlsplit(url)
        if parsed.path == "/":
            return probe_response(url, html, "text/html")
        if parsed.path == "/static/large.js":
            response = probe_response(url, js["example.com/static/large.js"], "application/javascript")
            response["body_size"] = 999999
            return response
        raise AssertionError(f"Unexpected request URL: {url}")

    originals = patch_workflow(scope_checker, oversized_probe)
    try:
        result = safe_js_endpoint_extraction_workflow("example.com", max_js_bytes=10)
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true("skipped_oversized" in statuses, "Oversized JS should be skipped")
        assert_true(result["inventory_candidates"] == [], "Oversized JS should not create inventory candidates")
    finally:
        restore_workflow(originals)


def test_http_probe_exception_does_not_crash():
    """Protects workflow stability when the HTTP helper raises."""
    calls = []
    html = html_with_scripts(["/static/app.js"])

    def raising_probe(url):
        calls.append(url)
        if urlsplit(url).path == "/":
            return probe_response(url, html, "text/html")
        raise RuntimeError("simulated JS fetch failure")

    originals = patch_workflow(scope_checker, raising_probe)
    try:
        result = safe_js_endpoint_extraction_workflow("example.com")
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true(result["stopped"] is False, "Workflow should not crash after helper exception")
        assert_true("request_error" in statuses, "Helper exception should become request_error")
        assert_true("safety" in result, "Safety metadata should still be returned")
    finally:
        restore_workflow(originals)


def test_http_probe_non_dict_result_does_not_crash():
    """Protects workflow stability when the HTTP helper returns malformed data."""
    calls = []
    html = html_with_scripts(["/static/app.js"])

    def malformed_probe(url):
        calls.append(url)
        if urlsplit(url).path == "/":
            return probe_response(url, html, "text/html")
        return "not a dict"

    originals = patch_workflow(scope_checker, malformed_probe)
    try:
        result = safe_js_endpoint_extraction_workflow("example.com")
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true(result["stopped"] is False, "Workflow should not crash on non-dict helper output")
        assert_true("request_error" in statuses, "Non-dict helper output should become request_error")
        assert_true("safety" in result, "Safety metadata should still be returned")
    finally:
        restore_workflow(originals)


def test_extracts_api_candidates_from_js_text():
    """Protects static extraction of API, versioned, GraphQL, OAuth, and URL candidates."""
    calls = []
    html = html_with_scripts(["/static/app.js"])
    js = {
        "example.com/static/app.js": (
            "fetch('/api/users');"
            "axios('/v1/items');"
            "const g = '/graphql';"
            "const o = '/oauth/callback';"
            "const full = 'https://example.com/v2/orders';"
        )
    }
    originals = patch_workflow(scope_checker, make_probe(calls, html, js))
    try:
        result = safe_js_endpoint_extraction_workflow("example.com")
        candidates = set(result.get("endpoint_candidates", []))

        assert_true("https://example.com/api/users" in candidates, "API path should be extracted")
        assert_true("https://example.com/v1/items" in candidates, "Versioned API path should be extracted")
        assert_true("https://example.com/graphql" in candidates, "GraphQL path should be extracted")
        assert_true("https://example.com/oauth/callback" in candidates, "OAuth path should be extracted")
        assert_true("https://example.com/v2/orders" in candidates, "Absolute URL should be extracted")
    finally:
        restore_workflow(originals)


def test_deduplicates_extracted_candidates():
    """Protects inventory de-duplication for repeated JS endpoint strings."""
    calls = []
    html = html_with_scripts(["/static/app.js"])
    js = {"example.com/static/app.js": "fetch('/api/users'); fetch('/api/users'); const u = '/api/users';"}
    originals = patch_workflow(scope_checker, make_probe(calls, html, js))
    try:
        result = safe_js_endpoint_extraction_workflow("example.com")

        assert_true(result["endpoint_candidates"] == ["https://example.com/api/users"], "Duplicate candidates should collapse")
        assert_true(len(result["inventory_candidates"]) == 1, "Duplicate candidates should create one inventory item")
    finally:
        restore_workflow(originals)


def test_returns_safety_metadata():
    """Protects required medium-risk safety flags and no-crawling declaration."""
    calls = []
    html = html_with_scripts(["/static/app.js"])
    js = {"example.com/static/app.js": "fetch('/api/users')"}
    originals = patch_workflow(scope_checker, make_probe(calls, html, js))
    try:
        result = safe_js_endpoint_extraction_workflow("example.com")
        safety = result.get("safety", {})

        assert_true(safety["scan_level"] == "medium-risk", "Workflow should be medium-risk")
        assert_true(safety["requests_sent"] == 2, "Workflow should report HTML plus JS request")
        assert_true(safety["fuzzing"] is False, "Workflow should not fuzz")
        assert_true(safety["bruteforce"] is False, "Workflow should not brute force")
        assert_true(safety["exploitation"] is False, "Workflow should not exploit")
        assert_true(safety["crawling"] is False, "Workflow should not crawl")
        assert_true(safety["credentialed_request"] is False, "Workflow should not use credentials")
    finally:
        restore_workflow(originals)


if __name__ == "__main__":
    test_out_of_scope_stops_without_requests()
    test_requests_target_html_and_limited_js_files_only()
    test_max_js_files_hard_cap_limits_requests_to_31()
    test_default_max_js_files_is_20()
    test_only_same_host_or_in_scope_js_is_requested()
    test_html_json_content_type_is_not_parsed()
    test_js_json_content_type_is_not_parsed()
    test_extracted_api_endpoints_are_not_requested()
    test_max_js_files_zero_does_not_request_js()
    test_max_js_files_limit_is_enforced()
    test_max_js_bytes_zero_does_not_crash()
    test_max_candidates_zero_does_not_crash()
    test_max_js_bytes_limit_is_enforced()
    test_http_probe_exception_does_not_crash()
    test_http_probe_non_dict_result_does_not_crash()
    test_extracts_api_candidates_from_js_text()
    test_deduplicates_extracted_candidates()
    test_returns_safety_metadata()

    print("All JS endpoint extraction workflow tests passed.")
