import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools import safety_metadata
from tools.safety_metadata import build_safety_metadata


def assert_true(condition, message):
    """Assert safety metadata helper behavior without any external request."""
    if not condition:
        raise AssertionError(message)


def test_default_safety_metadata_is_safe():
    """Protects the no-request, no-risk default baseline."""
    result = build_safety_metadata()

    assert_true(result["requests_sent"] == 0, "Default requests_sent should be 0")
    assert_true(result["scan_level"] == "safe", "Default scan_level should be safe")
    assert_true(result["fuzzing"] is False, "Default fuzzing should be false")
    assert_true(result["bruteforce"] is False, "Default bruteforce should be false")
    assert_true(result["exploitation"] is False, "Default exploitation should be false")
    assert_true(result["crawling"] is False, "Default crawling should be false")
    assert_true(result["credentialed_request"] is False, "Default credentialed_request should be false")


def test_requests_sent_normal_value_is_preserved():
    """Protects normal request accounting for future workflow adoption."""
    result = build_safety_metadata(requests_sent=3)

    assert_true(result["requests_sent"] == 3, "Normal request count should be preserved")


def test_negative_requests_sent_is_safely_clamped():
    """Protects fail-safe handling for impossible negative request counts."""
    result = build_safety_metadata(requests_sent=-5)

    assert_true(result["requests_sent"] == 0, "Negative request count should not be retained")


def test_non_numeric_requests_sent_does_not_crash():
    """Protects fail-safe handling for malformed request counts."""
    result = build_safety_metadata(requests_sent="not-a-number")

    assert_true(result["requests_sent"] == 0, "Non-numeric request count should fall back to 0")


def test_scan_level_can_be_low_risk():
    """Protects explicit scan_level metadata for low-risk workflows."""
    result = build_safety_metadata(scan_level="low-risk")

    assert_true(result["scan_level"] == "low-risk", "scan_level should preserve low-risk")


def test_crawling_true_is_preserved():
    """Protects explicit crawling metadata for bounded crawler workflows."""
    result = build_safety_metadata(crawling=True)

    assert_true(result["crawling"] is True, "crawling=True should be preserved")


def test_state_changing_defaults_false():
    """Protects the future state-changing safety flag default."""
    result = build_safety_metadata()

    assert_true(result["state_changing"] is False, "state_changing should default to false")


def test_helper_has_no_external_request_dependency():
    """Protects that safety metadata construction remains local-only."""
    assert_true("http_probe" not in safety_metadata.__dict__, "Helper should not import http_probe")
    assert_true("httpx" not in safety_metadata.__dict__, "Helper should not import httpx")
    assert_true("requests" not in safety_metadata.__dict__, "Helper should not import requests")


if __name__ == "__main__":
    test_default_safety_metadata_is_safe()
    test_requests_sent_normal_value_is_preserved()
    test_negative_requests_sent_is_safely_clamped()
    test_non_numeric_requests_sent_does_not_crash()
    test_scan_level_can_be_low_risk()
    test_crawling_true_is_preserved()
    test_state_changing_defaults_false()
    test_helper_has_no_external_request_dependency()

    print("All safety metadata tests passed.")
