from workflows.safe_http_probe_workflow import safe_http_probe_workflow
from workflows.safe_security_headers_workflow import safe_security_headers_workflow
from workflows.safe_cors_observation_workflow import safe_cors_observation_workflow
from workflows.safe_passive_recon_workflow import safe_passive_recon_workflow
from tools.scope_guard import check_scope


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def test_scope_in():
    result = check_scope("example.com")
    assert_true(result.get("in_scope") is True, "example.com should be in scope")


def test_scope_out():
    result = check_scope("google.com")
    assert_true(result.get("in_scope") is False, "google.com should be out of scope")


def test_out_of_scope_passive_recon_blocked():
    result = safe_passive_recon_workflow("google.com")

    assert_true(result.get("stopped") is True, "Out-of-scope target should be stopped")
    assert_true(
        result.get("safety", {}).get("requests_sent") == 0,
        "Out-of-scope target should send 0 requests"
    )


def test_in_scope_http_probe():
    result = safe_http_probe_workflow("example.com")

    assert_true(result.get("safety", {}).get("requests_sent") == 1, "HTTP probe should send 1 request")
    assert_true("probe_summary" in result, "HTTP probe result should include probe_summary")


def test_in_scope_security_headers():
    result = safe_security_headers_workflow("example.com")

    assert_true(result.get("safety", {}).get("requests_sent") == 1, "Security headers workflow should send 1 request")
    assert_true("validator_result" in result, "Security headers workflow should include validator_result")


def test_in_scope_cors_observation():
    result = safe_cors_observation_workflow("example.com")

    assert_true(result.get("safety", {}).get("requests_sent") == 1, "CORS workflow should send 1 request")
    assert_true("validator_result" in result, "CORS workflow should include validator_result")


def test_in_scope_passive_recon():
    result = safe_passive_recon_workflow("example.com")

    assert_true(result.get("safety", {}).get("requests_sent") == 3, "Passive recon should send 3 requests")
    assert_true("summary" in result, "Passive recon should include summary")
    assert_true("endpoint_classification" in result, "Passive recon should include endpoint_classification")


if __name__ == "__main__":
    test_scope_in()
    test_scope_out()
    test_out_of_scope_passive_recon_blocked()
    test_in_scope_http_probe()
    test_in_scope_security_headers()
    test_in_scope_cors_observation()
    test_in_scope_passive_recon()

    print("All workflow tests passed.")