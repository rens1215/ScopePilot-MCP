import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.crawl_queue import CrawlQueue
from tools.html_link_extractor import extract_html_links


def assert_true(condition, message):
    """
    Assert bounded crawl foundation behavior without external requests.

    These tests exercise only local HTML parsing, URL normalization, and queue
    policy. They do not import http_probe, call workflows, or send network
    traffic.
    """
    if not condition:
        raise AssertionError(message)


def test_html_link_extractor_extracts_anchor_href():
    """Protects extraction of explicit <a href> crawl candidates."""
    html = '<a href="/about">About</a>'

    result = extract_html_links(html, base_url="https://example.com")

    assert_true(result["ok"] is True, "Extractor should succeed")
    assert_true(result["links"][0]["normalized_url"] == "https://example.com/about", "Anchor href should normalize")
    assert_true(result["links"][0]["source_tag"] == "a", "Source tag should be recorded")


def test_html_link_extractor_extracts_script_src():
    """Protects extraction of explicit <script src> JavaScript candidates."""
    html = '<script src="/static/app.js"></script>'

    result = extract_html_links(html, base_url="https://example.com")

    assert_true(result["ok"] is True, "Extractor should succeed")
    assert_true(result["scripts"][0]["normalized_url"] == "https://example.com/static/app.js", "Script src should normalize")
    assert_true(result["scripts"][0]["source_tag"] == "script", "Source tag should be recorded")


def test_html_link_extractor_handles_relative_url():
    """Protects relative URL resolution through normalize_url."""
    html = '<a href="../api/users">Users</a>'

    result = extract_html_links(html, base_url="https://example.com/app/page")

    assert_true(result["links"][0]["normalized_url"] == "https://example.com/api/users", "Relative URL should resolve")


def test_html_link_extractor_rejects_javascript_scheme():
    """Protects against script pseudo-URLs becoming crawl targets."""
    html = '<a href="javascript:alert(1)">bad</a>'

    result = extract_html_links(html, base_url="https://example.com")

    assert_true(result["count"] == 0, "javascript: URL should not become a candidate")
    assert_true(len(result["skipped"]) == 1, "Rejected URL should be recorded as skipped")


def test_html_link_extractor_rejects_data_scheme():
    """Protects against data: pseudo-URLs becoming crawl targets."""
    html = '<a href="data:text/plain,hello">bad</a>'

    result = extract_html_links(html, base_url="https://example.com")

    assert_true(result["count"] == 0, "data: URL should not become a candidate")
    assert_true(len(result["skipped"]) == 1, "Rejected URL should be recorded as skipped")


def test_html_link_extractor_ignores_form_action():
    """Protects against treating form submissions as crawl targets."""
    html = '<form action="/submit"><input name="x"></form><a href="/safe">safe</a>'

    result = extract_html_links(html, base_url="https://example.com")
    normalized_urls = [item["normalized_url"] for item in result["links"]]

    assert_true("https://example.com/submit" not in normalized_urls, "Form action must not be extracted")
    assert_true("https://example.com/safe" in normalized_urls, "Anchor href should still be extracted")


def test_html_link_extractor_deduplicates_normalized_urls():
    """Protects de-duplication after URL normalization."""
    html = '<a href="/about#top">About</a><a href="https://example.com/about">About again</a>'

    result = extract_html_links(html, base_url="https://example.com")

    assert_true(result["count"] == 1, "Duplicate normalized URL should collapse")
    assert_true(len(result["skipped"]) == 1, "Duplicate should be recorded as skipped")


def test_html_link_extractor_enforces_max_links():
    """Protects local extraction limits before queueing."""
    html = '<a href="/one">1</a><a href="/two">2</a><script src="/app.js"></script>'

    result = extract_html_links(html, base_url="https://example.com", max_links=2)

    assert_true(result["count"] == 2, "Extractor should stop at max_links")
    assert_true(len(result["skipped"]) == 1, "Overflow item should be skipped")


def test_crawl_queue_adds_url():
    """Protects basic queue insertion without fetching the URL."""
    queue = CrawlQueue("https://example.com", max_pages=5, max_depth=2, max_requests=5)

    result = queue.add("/about", depth=1, source="unit_test")

    assert_true(result["accepted"] is True, "In-scope URL should be queued")
    assert_true(queue.items()[0]["url"] == "https://example.com/about", "Queued URL should be normalized")


def test_crawl_queue_deduplicates_url():
    """Protects queue de-duplication by normalized URL."""
    queue = CrawlQueue("https://example.com")

    first = queue.add("/about#top", depth=0, source="first")
    second = queue.add("https://example.com/about", depth=0, source="second")

    assert_true(first["accepted"] is True, "First URL should be accepted")
    assert_true(second["accepted"] is False, "Duplicate URL should be skipped")
    assert_true(queue.summary()["queued_count"] == 1, "Queue should contain one item")


def test_crawl_queue_limits_max_depth():
    """Protects max_depth policy before any future request is possible."""
    queue = CrawlQueue("https://example.com", max_depth=1)

    result = queue.add("/deep", depth=2, source="unit_test")

    assert_true(result["accepted"] is False, "URL beyond max_depth should be skipped")
    assert_true("max_depth" in result["reason"], "Skip reason should explain depth limit")


def test_crawl_queue_limits_max_pages():
    """Protects max_pages policy for bounded queue growth."""
    queue = CrawlQueue("https://example.com", max_pages=1, max_requests=10)

    first = queue.add("/one", depth=0, source="unit_test")
    second = queue.add("/two", depth=0, source="unit_test")

    assert_true(first["accepted"] is True, "First URL should be accepted")
    assert_true(second["accepted"] is False, "Second URL should exceed max_pages")
    assert_true(queue.summary()["queued_count"] == 1, "Queue should stay at max_pages")


def test_crawl_queue_rejects_out_of_scope_url():
    """Protects same-host/same-scope filtering in queue policy."""
    queue = CrawlQueue("https://example.com")

    result = queue.add("https://evil.test/admin", depth=0, source="unit_test")

    assert_true(result["accepted"] is False, "Out-of-scope URL should not enter queue")
    assert_true(queue.summary()["queued_count"] == 0, "Queue should remain empty")


if __name__ == "__main__":
    test_html_link_extractor_extracts_anchor_href()
    test_html_link_extractor_extracts_script_src()
    test_html_link_extractor_handles_relative_url()
    test_html_link_extractor_rejects_javascript_scheme()
    test_html_link_extractor_rejects_data_scheme()
    test_html_link_extractor_ignores_form_action()
    test_html_link_extractor_deduplicates_normalized_urls()
    test_html_link_extractor_enforces_max_links()
    test_crawl_queue_adds_url()
    test_crawl_queue_deduplicates_url()
    test_crawl_queue_limits_max_depth()
    test_crawl_queue_limits_max_pages()
    test_crawl_queue_rejects_out_of_scope_url()

    print("All bounded crawl foundation tests passed.")
