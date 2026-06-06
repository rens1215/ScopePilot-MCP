import sys
from pathlib import Path
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from workflows import safe_bounded_crawl_workflow as workflow_module
from workflows.safe_bounded_crawl_workflow import safe_bounded_crawl_workflow


def assert_true(condition, message):
    """
    Assert bounded crawl workflow behavior without real network traffic.

    These tests patch scope checks, HTTP probing, logging, and sleep. They do
    not send external requests and only verify bounded crawling control flow,
    inventory candidate creation, and safety metadata.
    """
    if not condition:
        raise AssertionError(message)


def patch_workflow(scope_checker, probe_func):
    original_scope = workflow_module.check_scope
    original_probe = workflow_module.http_probe
    original_log = workflow_module.log_event
    original_sleep = workflow_module.time.sleep

    workflow_module.check_scope = scope_checker
    workflow_module.http_probe = probe_func
    workflow_module.log_event = lambda message: None
    workflow_module.time.sleep = lambda seconds: None

    return original_scope, original_probe, original_log, original_sleep


def restore_workflow(originals):
    original_scope, original_probe, original_log, original_sleep = originals
    workflow_module.check_scope = original_scope
    workflow_module.http_probe = original_probe
    workflow_module.log_event = original_log
    workflow_module.time.sleep = original_sleep


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


def response(url, text, content_type="text/html"):
    return {
        "blocked": False,
        "status_code": 200,
        "final_url": url,
        "headers": {"content-type": content_type, "set-cookie": "secret=bad"},
        "content_type": content_type,
        "body_size": len(text.encode("utf-8")),
        "text": text,
    }


def make_probe(calls, pages, content_types=None):
    if content_types is None:
        content_types = {}

    def fake_probe(url):
        calls.append(url)
        parsed = urlsplit(url)
        path = parsed.path or "/"
        key = f"{parsed.hostname}{path}"

        if key not in pages:
            return response(url, "", "text/html")

        return response(url, pages[key], content_types.get(key, "text/html"))

    return fake_probe


def test_out_of_scope_stops_without_requests():
    """Protects scope-first behavior and zero requests for out-of-scope targets."""
    calls = []
    originals = patch_workflow(
        lambda target: scope_result(target, hostname="evil.test", in_scope=False),
        make_probe(calls, {}),
    )
    try:
        result = safe_bounded_crawl_workflow("evil.test", rate_delay_seconds=0)

        assert_true(result["stopped"] is True, "Out-of-scope target should stop")
        assert_true(result["safety"]["requests_sent"] == 0, "Out-of-scope target should send 0 requests")
        assert_true(calls == [], "HTTP helper should not be called out of scope")
    finally:
        restore_workflow(originals)


def test_max_pages_limit_is_enforced():
    """Protects max_pages so the crawler remains bounded."""
    calls = []
    pages = {
        "example.com/": '<a href="/one">one</a><a href="/two">two</a>',
        "example.com/one": '<a href="/three">three</a>',
        "example.com/two": "",
    }
    originals = patch_workflow(scope_checker, make_probe(calls, pages))
    try:
        result = safe_bounded_crawl_workflow("example.com", max_pages=2, max_requests=10, rate_delay_seconds=0)

        assert_true(result["summary"]["crawled_page_count"] == 2, "Crawler should process at most 2 pages")
        assert_true(result["safety"]["requests_sent"] == 2, "Request count should match page cap")
        assert_true(len(calls) == 2, "HTTP helper should be called twice")
    finally:
        restore_workflow(originals)


def test_max_depth_limit_is_enforced():
    """Protects max_depth so deeper discovered links are skipped before request."""
    calls = []
    pages = {
        "example.com/": '<a href="/level1">level1</a>',
        "example.com/level1": '<a href="/level2">level2</a>',
        "example.com/level2": "",
    }
    originals = patch_workflow(scope_checker, make_probe(calls, pages))
    try:
        result = safe_bounded_crawl_workflow("example.com", max_depth=1, max_requests=10, rate_delay_seconds=0)
        paths = {urlsplit(url).path for url in calls}

        assert_true("/level2" not in paths, "Depth 2 URL should not be requested")
        assert_true(any("max_depth" in item.get("reason", "") for item in result["skipped_urls"]), "Depth skip should be audited")
    finally:
        restore_workflow(originals)


def test_max_requests_limit_is_enforced():
    """Protects max_requests as the final hard request budget."""
    calls = []
    pages = {
        "example.com/": '<a href="/one">one</a><a href="/two">two</a><a href="/three">three</a>',
        "example.com/one": "",
        "example.com/two": "",
        "example.com/three": "",
    }
    originals = patch_workflow(scope_checker, make_probe(calls, pages))
    try:
        result = safe_bounded_crawl_workflow("example.com", max_pages=10, max_requests=2, rate_delay_seconds=0)

        assert_true(result["safety"]["requests_sent"] == 2, "requests_sent must not exceed max_requests")
        assert_true(len(calls) == 2, "HTTP helper should be called at most twice")
    finally:
        restore_workflow(originals)


def test_request_hard_cap_matches_risk_profile():
    """Protects the medium-risk profile cap even if caller asks for more."""
    calls = []
    links = "".join(f'<a href="/page{i}">page{i}</a>' for i in range(40))
    pages = {"example.com/": links}
    for index in range(40):
        pages[f"example.com/page{index}"] = ""

    originals = patch_workflow(scope_checker, make_probe(calls, pages))
    try:
        result = safe_bounded_crawl_workflow(
            "example.com",
            max_pages=100,
            max_requests=100,
            rate_delay_seconds=0,
        )

        assert_true(result["safety"]["requests_sent"] == 30, "requests_sent must stay at the hard cap")
        assert_true(len(calls) == 30, "HTTP helper should not be called more than 30 times")
        assert_true(result["summary"]["max_requests"] == 30, "Summary should expose the effective request cap")
        assert_true(result["summary"]["hard_max_requests"] == 30, "Summary should expose the hard request cap")
    finally:
        restore_workflow(originals)


def test_out_of_scope_link_is_not_requested():
    """Protects same-host/configured-scope filtering for discovered links."""
    calls = []
    pages = {
        "example.com/": '<a href="https://evil.test/admin">evil</a><a href="/safe">safe</a>',
        "example.com/safe": "",
    }
    originals = patch_workflow(scope_checker, make_probe(calls, pages))
    try:
        result = safe_bounded_crawl_workflow("example.com", max_requests=5, rate_delay_seconds=0)
        hosts = {urlsplit(url).hostname for url in calls}

        assert_true("evil.test" not in hosts, "Out-of-scope host should not be requested")
        assert_true(any("outside target host" in item.get("reason", "") for item in result["skipped_urls"]), "Out-of-scope skip should be audited")
    finally:
        restore_workflow(originals)


def test_form_action_is_not_requested():
    """Protects against submitting or crawling form action targets."""
    calls = []
    pages = {
        "example.com/": '<form action="/submit" method="post"></form><a href="/safe">safe</a>',
        "example.com/safe": "",
    }
    originals = patch_workflow(scope_checker, make_probe(calls, pages))
    try:
        safe_bounded_crawl_workflow("example.com", max_requests=5, rate_delay_seconds=0)
        paths = {urlsplit(url).path for url in calls}

        assert_true("/submit" not in paths, "Form action must not be requested")
        assert_true("/safe" in paths, "Anchor href should still be crawled")
    finally:
        restore_workflow(originals)


def test_state_changing_methods_do_not_appear():
    """Protects that the workflow never models POST/PUT/PATCH/DELETE requests."""
    calls = []
    pages = {"example.com/": '<a href="/safe">safe</a>', "example.com/safe": ""}
    originals = patch_workflow(scope_checker, make_probe(calls, pages))
    try:
        result = safe_bounded_crawl_workflow("example.com", max_requests=2, rate_delay_seconds=0)
        result_text = str(result)

        assert_true(all(isinstance(url, str) for url in calls), "Mock probe receives only URL strings")
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            assert_true(method not in result_text, f"{method} should not appear in workflow output")
    finally:
        restore_workflow(originals)


def test_unsupported_content_type_is_not_parsed():
    """Protects content-type gate so non-HTML bodies are not parsed for links."""
    calls = []
    pages = {"example.com/": '<a href="/api/users">api</a>'}
    content_types = {"example.com/": "application/json"}
    originals = patch_workflow(scope_checker, make_probe(calls, pages, content_types))
    try:
        result = safe_bounded_crawl_workflow("example.com", max_requests=5, rate_delay_seconds=0)
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true(statuses == ["unsupported_content_type"], "JSON response should not be parsed")
        assert_true(len(calls) == 1, "Links in JSON-like response should not be requested")
    finally:
        restore_workflow(originals)


def test_http_probe_exception_becomes_request_error():
    """Protects workflow stability when the HTTP helper raises."""
    calls = []

    def raising_probe(url):
        calls.append(url)
        raise RuntimeError("simulated probe failure")

    originals = patch_workflow(scope_checker, raising_probe)
    try:
        result = safe_bounded_crawl_workflow("example.com", max_requests=1, rate_delay_seconds=0)
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true(result["stopped"] is False, "Workflow should not crash on helper exception")
        assert_true("request_error" in statuses, "Helper exception should become request_error")
        assert_true(result["safety"]["requests_sent"] == 1, "Attempted helper call should count")
    finally:
        restore_workflow(originals)


def test_http_probe_non_dict_becomes_request_error():
    """Protects workflow stability when the HTTP helper returns malformed data."""
    calls = []

    def malformed_probe(url):
        calls.append(url)
        return "not a dict"

    originals = patch_workflow(scope_checker, malformed_probe)
    try:
        result = safe_bounded_crawl_workflow("example.com", max_requests=1, rate_delay_seconds=0)
        statuses = [observation.get("status") for observation in result.get("observations", [])]

        assert_true(result["stopped"] is False, "Workflow should not crash on non-dict helper output")
        assert_true("request_error" in statuses, "Non-dict helper output should become request_error")
        assert_true(result["safety"]["requests_sent"] == 1, "Malformed helper call should count")
    finally:
        restore_workflow(originals)


def test_script_src_becomes_inventory_candidate_but_is_not_downloaded():
    """Protects that script src is inventoried but not fetched by the crawler."""
    calls = []
    pages = {"example.com/": '<script src="/static/app.js"></script>'}
    originals = patch_workflow(scope_checker, make_probe(calls, pages))
    try:
        result = safe_bounded_crawl_workflow("example.com", max_requests=5, rate_delay_seconds=0)
        paths = {urlsplit(url).path for url in calls}
        script_candidates = [
            item for item in result["inventory_candidates"]
            if item.get("source") == "html_script_tag"
        ]

        assert_true("/static/app.js" not in paths, "Crawler must not download JS files")
        assert_true(len(script_candidates) == 1, "Script src should become an inventory candidate")
        assert_true(script_candidates[0]["normalized_url"] == "https://example.com/static/app.js", "Script candidate should normalize")
    finally:
        restore_workflow(originals)


def test_js_api_endpoint_is_not_requested():
    """Protects that JS endpoint extraction is not performed inside crawler."""
    calls = []
    pages = {
        "example.com/": (
            '<script src="/static/app.js"></script>'
            '<script>fetch("/api/users")</script>'
        )
    }
    originals = patch_workflow(scope_checker, make_probe(calls, pages))
    try:
        safe_bounded_crawl_workflow("example.com", max_requests=5, rate_delay_seconds=0)
        paths = {urlsplit(url).path for url in calls}

        assert_true("/static/app.js" not in paths, "Crawler should not download JS")
        assert_true("/api/users" not in paths, "Crawler should not request JS-discovered API endpoints")
    finally:
        restore_workflow(originals)


def test_safety_metadata_marks_crawling_true():
    """Protects required safety metadata for bounded crawling."""
    calls = []
    pages = {"example.com/": '<a href="/safe">safe</a>', "example.com/safe": ""}
    originals = patch_workflow(scope_checker, make_probe(calls, pages))
    try:
        result = safe_bounded_crawl_workflow("example.com", max_requests=2, rate_delay_seconds=0)
        safety = result.get("safety", {})

        assert_true(safety["scan_level"] == "medium-risk", "Bounded crawler should be medium risk")
        assert_true(safety["crawling"] is True, "safety.crawling should be true")
        assert_true(safety["fuzzing"] is False, "Workflow should not fuzz")
        assert_true(safety["bruteforce"] is False, "Workflow should not brute force")
        assert_true(safety["exploitation"] is False, "Workflow should not exploit")
        assert_true(safety["credentialed_request"] is False, "Workflow should not use credentials")
        assert_true(safety["requests_sent"] == 2, "Safety should report request count")
    finally:
        restore_workflow(originals)


if __name__ == "__main__":
    test_out_of_scope_stops_without_requests()
    test_max_pages_limit_is_enforced()
    test_max_depth_limit_is_enforced()
    test_max_requests_limit_is_enforced()
    test_request_hard_cap_matches_risk_profile()
    test_out_of_scope_link_is_not_requested()
    test_form_action_is_not_requested()
    test_state_changing_methods_do_not_appear()
    test_unsupported_content_type_is_not_parsed()
    test_http_probe_exception_becomes_request_error()
    test_http_probe_non_dict_becomes_request_error()
    test_script_src_becomes_inventory_candidate_but_is_not_downloaded()
    test_js_api_endpoint_is_not_requested()
    test_safety_metadata_marks_crawling_true()

    print("All bounded crawl workflow tests passed.")
