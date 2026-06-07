import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools import inventory_candidate_builder
from tools.inventory_candidate_builder import (
    build_validated_inventory_candidate,
    sanitize_inventory_evidence,
)


def assert_true(condition, message):
    """Assert inventory candidate helper behavior without network or workflow calls."""
    if not condition:
        raise AssertionError(message)


def test_sanitize_inventory_evidence_keeps_status_code():
    """Protects status_code as safe inventory evidence metadata."""
    result = sanitize_inventory_evidence({"status_code": 200})

    assert_true(result["status_code"] == 200, "status_code should be preserved")


def test_sanitize_inventory_evidence_keeps_content_type():
    """Protects content_type as safe inventory evidence metadata."""
    result = sanitize_inventory_evidence({"content_type": "text/html"})

    assert_true(result["content_type"] == "text/html", "content_type should be preserved")


def test_sanitize_inventory_evidence_keeps_body_size():
    """Protects body_size while still excluding full response bodies."""
    result = sanitize_inventory_evidence({"body_size": 1234})

    assert_true(result["body_size"] == 1234, "body_size should be preserved")


def test_sanitize_inventory_evidence_keeps_headers_summary():
    """Protects safe header metadata retention through header summary filtering."""
    result = sanitize_inventory_evidence(
        {
            "headers_summary": {
                "Content-Type": "text/html",
                "Cache-Control": "max-age=0",
            }
        }
    )

    assert_true(
        result["headers_summary"] == {"content-type": "text/html", "cache-control": "max-age=0"},
        "headers_summary should preserve safe headers with normalized keys",
    )


def test_sanitize_inventory_evidence_removes_response_bodies():
    """Protects against storing full body-like response fields."""
    result = sanitize_inventory_evidence(
        {
            "body": "secret body",
            "text": "secret text",
            "response_text": "secret response",
            "content": "secret content",
            "status_code": 200,
        }
    )

    assert_true("body" not in result, "body should be removed")
    assert_true("text" not in result, "text should be removed")
    assert_true("response_text" not in result, "response_text should be removed")
    assert_true("content" not in result, "content should be removed")
    assert_true(result["status_code"] == 200, "safe metadata should remain")


def test_sanitize_inventory_evidence_removes_cookie_and_authorization():
    """Protects against storing cookie or authorization material."""
    result = sanitize_inventory_evidence(
        {
            "cookie": "session=secret",
            "set-cookie": "session=secret",
            "authorization": "Bearer secret",
            "content_type": "text/html",
        }
    )

    assert_true("cookie" not in result, "cookie should be removed")
    assert_true("set-cookie" not in result, "set-cookie should be removed")
    assert_true("authorization" not in result, "authorization should be removed")
    assert_true(result["content_type"] == "text/html", "safe metadata should remain")


def test_sanitize_inventory_evidence_removes_token_secret_api_key():
    """Protects against storing token-like, secret-like, or API-key fields."""
    result = sanitize_inventory_evidence(
        {
            "access_token": "token",
            "client_secret": "secret",
            "x-api-key": "key",
            "status_code": 200,
        }
    )

    assert_true("access_token" not in result, "token-like fields should be removed")
    assert_true("client_secret" not in result, "secret-like fields should be removed")
    assert_true("x-api-key" not in result, "api-key fields should be removed")
    assert_true(result["status_code"] == 200, "safe metadata should remain")


def test_sanitize_inventory_evidence_non_dict_does_not_crash():
    """Protects fail-safe handling for malformed evidence inputs."""
    result = sanitize_inventory_evidence("not a dict")

    assert_true(result == {}, "Non-dict evidence should become empty evidence")


def test_build_validated_inventory_candidate_has_required_fields():
    """Protects base candidate schema creation through build_inventory_item."""
    item = build_validated_inventory_candidate(
        target="example.com",
        raw_url="/api/users",
        normalized_url="https://example.com/api/users",
        source="unit_test",
        discovered_by="test_inventory_candidate_builder",
        evidence={"status_code": 200},
    )

    required = {
        "target",
        "url",
        "normalized_url",
        "source",
        "method_guess",
        "endpoint_type",
        "priority",
        "confidence",
        "discovered_by",
        "evidence",
        "safety",
        "recommended_next_skill",
        "recommended_next_steps",
        "notes",
    }

    assert_true(required.issubset(item.keys()), "Candidate should include required inventory item fields")


def test_build_validated_inventory_candidate_has_validator_result():
    """Protects conservative validator metadata being attached to candidates."""
    item = build_validated_inventory_candidate(
        "example.com",
        "/api/users",
        "https://example.com/api/users",
        "unit_test",
        "test_inventory_candidate_builder",
    )

    assert_true("validator_result" in item, "Candidate should include validator_result")
    assert_true(isinstance(item["validator_result"], dict), "validator_result should be a dict")


def test_build_validated_inventory_candidate_writes_endpoint_type():
    """Protects endpoint_type copy-back from validator result."""
    item = build_validated_inventory_candidate(
        "example.com",
        "/api/users",
        "https://example.com/api/users",
        "unit_test",
        "test_inventory_candidate_builder",
    )

    assert_true(item["endpoint_type"], "endpoint_type should be populated")


def test_build_validated_inventory_candidate_writes_priority():
    """Protects priority copy-back from validator result."""
    item = build_validated_inventory_candidate(
        "example.com",
        "/api/users",
        "https://example.com/api/users",
        "unit_test",
        "test_inventory_candidate_builder",
    )

    assert_true(item["priority"], "priority should be populated")


def test_build_validated_inventory_candidate_classifies_api_path():
    """Protects /api/ path classification or at least safe non-crashing behavior."""
    item = build_validated_inventory_candidate(
        "example.com",
        "/api/users",
        "https://example.com/api/users",
        "unit_test",
        "test_inventory_candidate_builder",
    )

    assert_true(item["validator_result"]["valid"] is True, "API candidate should validate as inventory")
    assert_true(item["endpoint_type"] in {"api", "unknown", "frontend"}, "API candidate should not crash classification")


def test_build_validated_inventory_candidate_handles_empty_urls():
    """Protects fail-safe handling for missing URL values."""
    item = build_validated_inventory_candidate(
        "example.com",
        "",
        "",
        "unit_test",
        "test_inventory_candidate_builder",
        evidence="not a dict",
    )

    assert_true(item["url"] == "", "Empty raw_url should be preserved safely")
    assert_true(item["normalized_url"] == "", "Empty normalized_url should be preserved safely")
    assert_true(item["validator_result"]["valid"] is False, "Missing normalized_url should fail validation safely")


def test_helper_does_not_import_network_or_workflows():
    """Protects helper from network, HTTP probing, or workflow dependencies."""
    assert_true("http_probe" not in inventory_candidate_builder.__dict__, "Helper should not import http_probe")
    assert_true("httpx" not in inventory_candidate_builder.__dict__, "Helper should not import httpx")
    assert_true("requests" not in inventory_candidate_builder.__dict__, "Helper should not import requests")
    assert_true("workflows" not in inventory_candidate_builder.__dict__, "Helper should not import workflows")


if __name__ == "__main__":
    test_sanitize_inventory_evidence_keeps_status_code()
    test_sanitize_inventory_evidence_keeps_content_type()
    test_sanitize_inventory_evidence_keeps_body_size()
    test_sanitize_inventory_evidence_keeps_headers_summary()
    test_sanitize_inventory_evidence_removes_response_bodies()
    test_sanitize_inventory_evidence_removes_cookie_and_authorization()
    test_sanitize_inventory_evidence_removes_token_secret_api_key()
    test_sanitize_inventory_evidence_non_dict_does_not_crash()
    test_build_validated_inventory_candidate_has_required_fields()
    test_build_validated_inventory_candidate_has_validator_result()
    test_build_validated_inventory_candidate_writes_endpoint_type()
    test_build_validated_inventory_candidate_writes_priority()
    test_build_validated_inventory_candidate_classifies_api_path()
    test_build_validated_inventory_candidate_handles_empty_urls()
    test_helper_does_not_import_network_or_workflows()

    print("All inventory candidate builder tests passed.")
