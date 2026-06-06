import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.endpoint_inventory import (
    build_inventory_item,
    dedupe_inventory_items,
    summarize_inventory,
)
from tools.url_normalizer import normalize_url
from validators.inventory_validator import validate_inventory_item


def assert_true(condition, message):
    """
    Assert local inventory test conditions without external dependencies.

    These tests never send network requests. They only exercise string parsing,
    dictionary construction, de-duplication, local classification, and summary
    aggregation.
    """
    if not condition:
        raise AssertionError(message)


def test_normalize_url_removes_fragment():
    """Protects fragment removal so inventory keys ignore client-side anchors."""
    result = normalize_url("https://example.com/path?x=1#section")

    assert_true(result["ok"] is True, "URL should normalize")
    assert_true(result["normalized_url"] == "https://example.com/path?x=1", "Fragment should be removed")
    assert_true(result["query"] == "x=1", "Query should be preserved")


def test_normalize_url_lowercases_scheme_and_hostname():
    """Protects stable URL casing for de-duplication."""
    result = normalize_url("HTTPS://Example.COM/Admin")

    assert_true(result["ok"] is True, "URL should normalize")
    assert_true(result["scheme"] == "https", "Scheme should be lowercase")
    assert_true(result["hostname"] == "example.com", "Hostname should be lowercase")
    assert_true(result["normalized_url"] == "https://example.com/Admin", "Path casing should be preserved")


def test_normalize_url_supports_base_url_relative_path():
    """Protects base_url plus relative-path normalization."""
    result = normalize_url("../api/users?active=true", base_url="https://example.com/app/page")

    assert_true(result["ok"] is True, "Relative URL should normalize with base")
    assert_true(result["normalized_url"] == "https://example.com/api/users?active=true", "Relative path should resolve")


def test_normalize_url_rejects_javascript_scheme():
    """Protects inventory from script pseudo-URLs."""
    result = normalize_url("javascript:alert(1)")

    assert_true(result["ok"] is False, "javascript: URL should be rejected")
    assert_true("Unsupported" in result["error"], "Rejection should include error")


def test_normalize_url_rejects_data_scheme():
    """Protects inventory from data: pseudo-URLs."""
    result = normalize_url("data:text/plain,hello")

    assert_true(result["ok"] is False, "data: URL should be rejected")
    assert_true("Unsupported" in result["error"], "Rejection should include error")


def test_build_inventory_item_has_required_fields():
    """Protects the baseline in-memory inventory item schema."""
    item = build_inventory_item(
        target="example.com",
        url="https://example.com/api/users",
        normalized_url="https://example.com/api/users",
        source="manual",
        discovered_by="unit_test",
    )

    for field in (
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
    ):
        assert_true(field in item, f"Inventory item should include {field}")

    assert_true(item["safety"]["requests_sent"] == 0, "Inventory foundation should send no requests")


def test_dedupe_inventory_items_removes_duplicate_normalized_url():
    """Protects de-duplication by normalized_url."""
    first = build_inventory_item("example.com", "/api/users", "https://example.com/api/users", "sitemap")
    second = build_inventory_item("example.com", "/api/users#x", "https://example.com/api/users", "manual")

    deduped = dedupe_inventory_items([first, second])

    assert_true(len(deduped) == 1, "Duplicate normalized URL should be removed")
    assert_true(deduped[0]["source"] == "sitemap", "First discovery should be preserved")


def test_validate_inventory_item_classifies_api_endpoint():
    """Protects conservative API endpoint classification."""
    item = build_inventory_item("example.com", "/api/users", "https://example.com/api/users", "manual")

    result = validate_inventory_item(item)

    assert_true(result["valid"] is True, "API item should be valid")
    assert_true(result["endpoint_type"] == "api", "API path should classify as api")
    assert_true(result["priority"] in ("medium", "high"), "API endpoint should receive elevated priority")


def test_validate_inventory_item_classifies_login_endpoint():
    """Protects auth/login endpoint classification."""
    item = build_inventory_item("example.com", "/login", "https://example.com/login", "manual")

    result = validate_inventory_item(item)

    assert_true(result["valid"] is True, "Login item should be valid")
    assert_true(result["endpoint_type"] == "auth_page", "Login path should classify as auth_page")
    assert_true(result["priority"] == "high", "Auth page should receive high priority")


def test_validate_inventory_item_classifies_static_asset():
    """Protects static asset noise reduction."""
    item = build_inventory_item("example.com", "/static/app.js", "https://example.com/static/app.js", "html_script_tag")

    result = validate_inventory_item(item)

    assert_true(result["valid"] is True, "Static item should be valid")
    assert_true(result["endpoint_type"] == "static_asset", "JS asset should classify as static_asset")
    assert_true(result["priority"] == "low", "Static asset should stay low priority")


def test_summarize_inventory_groups_by_source_type_and_priority():
    """Protects local inventory aggregation by source, endpoint type, and priority."""
    api_item = build_inventory_item(
        "example.com",
        "/api/users",
        "https://example.com/api/users",
        "sitemap",
        endpoint_type="api",
        priority="medium",
    )
    auth_item = build_inventory_item(
        "example.com",
        "/login",
        "https://example.com/login",
        "manual",
        endpoint_type="auth_page",
        priority="high",
    )
    asset_item = build_inventory_item(
        "example.com",
        "/static/app.js",
        "https://example.com/static/app.js",
        "html_script_tag",
        endpoint_type="static_asset",
        priority="low",
    )

    summary = summarize_inventory([api_item, auth_item, asset_item])

    assert_true(summary["total_items"] == 3, "Summary should count all items")
    assert_true(summary["by_source"]["sitemap"] == 1, "Summary should group by source")
    assert_true(summary["by_endpoint_type"]["api"] == 1, "Summary should group by endpoint type")
    assert_true(summary["by_priority"]["high"] == 1, "Summary should group by priority")


if __name__ == "__main__":
    test_normalize_url_removes_fragment()
    test_normalize_url_lowercases_scheme_and_hostname()
    test_normalize_url_supports_base_url_relative_path()
    test_normalize_url_rejects_javascript_scheme()
    test_normalize_url_rejects_data_scheme()
    test_build_inventory_item_has_required_fields()
    test_dedupe_inventory_items_removes_duplicate_normalized_url()
    test_validate_inventory_item_classifies_api_endpoint()
    test_validate_inventory_item_classifies_login_endpoint()
    test_validate_inventory_item_classifies_static_asset()
    test_summarize_inventory_groups_by_source_type_and_priority()

    print("All attack surface inventory tests passed.")
