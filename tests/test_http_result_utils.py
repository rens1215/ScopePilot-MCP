import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools import http_result_utils
from tools.http_result_utils import (
    base_http_observation,
    get_content_type,
    headers_summary,
    is_allowed_content_type,
    probe_body_text,
    safe_http_probe_call,
)


def assert_true(condition, message):
    """Assert HTTP result utility behavior without real network traffic."""
    if not condition:
        raise AssertionError(message)


def test_safe_http_probe_call_returns_dict_result():
    """Protects normal mock probe result handling without real network use."""
    calls = []

    def fake_probe(url):
        calls.append(url)
        return {"url": url, "status_code": 200}

    result, called = safe_http_probe_call("https://example.com", probe_func=fake_probe)

    assert_true(called is True, "Mock probe should be marked called")
    assert_true(result["status_code"] == 200, "Dict result should be returned")
    assert_true(calls == ["https://example.com"], "Mock probe should receive URL")


def test_safe_http_probe_call_handles_exception():
    """Protects fail-safe request_error conversion when a mock probe raises."""
    def raising_probe(url):
        raise RuntimeError("simulated failure")

    result, called = safe_http_probe_call("https://example.com", probe_func=raising_probe)

    assert_true(called is True, "Raised probe should still count as attempted")
    assert_true(result["status"] == "request_error", "Exception should become request_error")
    assert_true("simulated failure" in result["error"], "Error should preserve useful context")


def test_safe_http_probe_call_handles_non_dict():
    """Protects fail-safe request_error conversion for malformed probe output."""
    result, called = safe_http_probe_call("https://example.com", probe_func=lambda url: "bad")

    assert_true(called is True, "Malformed probe should still count as attempted")
    assert_true(result["status"] == "request_error", "Non-dict result should become request_error")
    assert_true("non-dict" in result["error"], "Error should describe malformed output")


def test_get_content_type_from_field():
    """Protects direct content_type extraction."""
    content_type = get_content_type({"content_type": "Text/HTML"})

    assert_true(content_type == "text/html", "Content-Type should normalize casing")


def test_get_content_type_from_headers():
    """Protects case-insensitive header Content-Type extraction."""
    content_type = get_content_type({"headers": {"Content-Type": "application/json"}})

    assert_true(content_type == "application/json", "Header content-type should be extracted")


def test_get_content_type_strips_charset():
    """Protects stable media-type comparison by removing charset parameters."""
    content_type = get_content_type({"content_type": "text/html; charset=utf-8"})

    assert_true(content_type == "text/html", "Content-Type parameters should be stripped")


def test_headers_summary_keeps_safe_headers():
    """Protects preservation of non-sensitive response metadata headers."""
    summary = headers_summary(
        {
            "Content-Type": "text/html",
            "Content-Length": "123",
            "Last-Modified": "Sat, 01 Jan 2022 00:00:00 GMT",
            "ETag": '"abc"',
            "Cache-Control": "max-age=0",
            "Location": "https://example.com/login",
        }
    )

    assert_true(set(summary.keys()) == {
        "content-type",
        "content-length",
        "last-modified",
        "etag",
        "cache-control",
        "location",
    }, "Safe headers should be retained with lowercase keys")


def test_headers_summary_removes_set_cookie():
    """Protects against storing cookie material in safe header summaries."""
    summary = headers_summary({"Set-Cookie": "session=secret", "Content-Type": "text/html"})

    assert_true("set-cookie" not in summary, "Set-Cookie must not be retained")
    assert_true(summary["content-type"] == "text/html", "Safe headers should still be retained")


def test_headers_summary_removes_authorization():
    """Protects against storing authorization material."""
    summary = headers_summary({"Authorization": "Bearer secret", "Content-Type": "text/html"})

    assert_true("authorization" not in summary, "Authorization must not be retained")


def test_headers_summary_removes_token_and_secret_headers():
    """Protects against storing token-like or secret-like header names."""
    summary = headers_summary(
        {
            "X-Api-Key": "secret",
            "X-Auth-Token": "token",
            "X-Secret-Value": "secret",
            "Content-Type": "text/html",
        }
    )

    assert_true("x-api-key" not in summary, "API key header must not be retained")
    assert_true("x-auth-token" not in summary, "Token header must not be retained")
    assert_true("x-secret-value" not in summary, "Secret header must not be retained")
    assert_true(summary == {"content-type": "text/html"}, "Only safe headers should remain")


def test_probe_body_text_supports_text():
    """Protects local text extraction from mock probe metadata."""
    body = probe_body_text({"text": "hello"})

    assert_true(body == "hello", "Text body should be returned")


def test_probe_body_text_supports_bytes():
    """Protects byte body decoding with replacement for invalid bytes."""
    body = probe_body_text({"content": b"hello \xff"})

    assert_true(body == "hello \ufffd", "Bytes should decode with replacement")


def test_base_http_observation_excludes_full_body():
    """Protects observation output from storing full response bodies."""
    observation = base_http_observation(
        "https://example.com",
        {"status_code": 200, "content_type": "text/html", "body": "<html>full body</html>"},
        "parsed",
    )

    assert_true("body" not in observation, "Observation must not include body")
    assert_true("text" not in observation, "Observation must not include text")


def test_base_http_observation_excludes_sensitive_headers():
    """Protects observation output from storing sensitive headers."""
    observation = base_http_observation(
        "https://example.com",
        {
            "status_code": 200,
            "headers": {
                "Content-Type": "text/html",
                "Set-Cookie": "session=secret",
                "Authorization": "Bearer secret",
            },
        },
        "parsed",
    )

    summary = observation["headers_summary"]
    assert_true(summary == {"content-type": "text/html"}, "Only safe headers should be summarized")


def test_is_allowed_content_type_matches_allowed_set():
    """Protects allowed content-type checks for future workflow gates."""
    allowed = {"text/html", "application/xhtml+xml"}

    assert_true(is_allowed_content_type("text/html; charset=utf-8", allowed) is True, "HTML should be allowed")
    assert_true(is_allowed_content_type("application/json", allowed) is False, "JSON should not be allowed")


def test_helpers_do_not_import_network_or_workflows():
    """Protects import-time behavior from network/workflow dependencies."""
    assert_true("http_probe" not in http_result_utils.__dict__, "Module should not import http_probe at import time")
    assert_true("httpx" not in http_result_utils.__dict__, "Module should not import httpx")
    assert_true("requests" not in http_result_utils.__dict__, "Module should not import requests")
    assert_true("workflows" not in http_result_utils.__dict__, "Module should not import workflows")


if __name__ == "__main__":
    test_safe_http_probe_call_returns_dict_result()
    test_safe_http_probe_call_handles_exception()
    test_safe_http_probe_call_handles_non_dict()
    test_get_content_type_from_field()
    test_get_content_type_from_headers()
    test_get_content_type_strips_charset()
    test_headers_summary_keeps_safe_headers()
    test_headers_summary_removes_set_cookie()
    test_headers_summary_removes_authorization()
    test_headers_summary_removes_token_and_secret_headers()
    test_probe_body_text_supports_text()
    test_probe_body_text_supports_bytes()
    test_base_http_observation_excludes_full_body()
    test_base_http_observation_excludes_sensitive_headers()
    test_is_allowed_content_type_matches_allowed_set()
    test_helpers_do_not_import_network_or_workflows()

    print("All HTTP result utility tests passed.")
