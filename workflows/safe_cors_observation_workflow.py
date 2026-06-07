from tools.http_result_utils import base_http_observation, get_content_type, headers_summary
from tools.logger import log_event
from tools.result_schema import build_workflow_result
from tools.safety_metadata import build_safety_metadata
from tools.scope_guard import check_scope
from tools.storage import save_finding

from validators.cors_validator import validate_cors

try:
    import httpx
except ImportError:
    httpx = None

try:
    from tools.endpoint_classifier import classify_endpoint
except ImportError:
    classify_endpoint = None


DEFAULT_TEST_ORIGIN = "https://example-attacker.invalid"

SAFE_CORS_HEADER_NAMES = {
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "vary",
}

SENSITIVE_MARKERS = {
    "cookie",
    "authorization",
    "token",
    "secret",
    "api-key",
    "apikey",
}


def _normalize_url(target: str) -> str:
    if "://" not in target:
        return "https://" + target
    return target


def _extract_title(html: str) -> str | None:
    lower = html.lower()
    start = lower.find("<title>")
    end = lower.find("</title>")

    if start == -1 or end == -1 or end <= start:
        return None

    return html[start + len("<title>"):end].strip()[:200]


def _normalize_headers(headers: dict | None) -> dict:
    if not isinstance(headers, dict):
        return {}

    return {
        str(key).lower(): value
        for key, value in headers.items()
    }


def _safety(requests_sent: int, scan_level: str = "low-risk") -> dict:
    return build_safety_metadata(requests_sent=requests_sent, scan_level=scan_level)


def _contains_sensitive_marker(value) -> bool:
    lowered = str(value or "").lower()
    return any(marker in lowered for marker in SENSITIVE_MARKERS)


def _safe_test_origin(test_origin: str) -> str:
    """
    Keep the CORS test origin harmless and credential-free.

    The default origin is an invalid domain reserved for safe observation. If a
    caller supplies a credential-like or secret-like origin, the workflow falls
    back to the harmless default so output never persists sensitive origin data.
    """
    candidate = str(test_origin or "").strip()
    if not candidate:
        return DEFAULT_TEST_ORIGIN
    if "@" in candidate or _contains_sensitive_marker(candidate):
        return DEFAULT_TEST_ORIGIN
    return candidate


def _safe_cors_headers(headers: dict | None) -> dict:
    """
    Keep only safe CORS response headers.

    This excludes cookies, authorization material, token-like values, and
    secret-like values while preserving the CORS metadata needed by the
    conservative validator.
    """
    normalized = _normalize_headers(headers)
    safe = {}

    for key in SAFE_CORS_HEADER_NAMES:
        value = normalized.get(key)
        if value is None:
            safe[key] = None
            continue
        if _contains_sensitive_marker(key) or _contains_sensitive_marker(value):
            safe[key] = None
            continue
        safe[key] = value

    return safe


def _safe_cors_result_for_output(cors_result: dict) -> dict:
    safe_headers = _safe_cors_headers(cors_result.get("headers"))
    return {
        "target": cors_result.get("target"),
        "url": cors_result.get("url"),
        "blocked": bool(cors_result.get("blocked")),
        "status_code": cors_result.get("status_code"),
        "final_url": cors_result.get("final_url"),
        "redirect_history": list(cors_result.get("redirect_history", []))
        if isinstance(cors_result.get("redirect_history"), list)
        else [],
        "headers": safe_headers,
        "cors_headers": _safe_cors_headers(cors_result.get("cors_headers") or safe_headers),
        "origin_tested": _safe_test_origin(cors_result.get("origin_tested", DEFAULT_TEST_ORIGIN)),
        "origin_reflected": bool(cors_result.get("origin_reflected", False)),
        "content_type": get_content_type(cors_result),
        "title": cors_result.get("title"),
        "body_size": cors_result.get("body_size"),
        "error": cors_result.get("error"),
    }


def _safe_error_result(target: str, url: str, test_origin: str, error: str) -> dict:
    return {
        "target": target,
        "url": url,
        "blocked": False,
        "error": error,
        "origin_tested": _safe_test_origin(test_origin),
        "origin_reflected": False,
        "headers": {},
        "cors_headers": {},
    }


def _cors_observation_request(target: str, url: str, test_origin: str) -> dict:
    """
    Send the single low-risk CORS observation request.

    This helper intentionally uses no cookies, tokens, sessions, credentials, or
    state-changing methods. It performs one GET with a harmless Origin header
    and does not crawl, fuzz, brute force, exploit, submit forms, or store full
    response bodies.
    """
    if httpx is None:
        raise RuntimeError("httpx helper is unavailable.")

    with httpx.Client(
        follow_redirects=True,
        timeout=10.0,
        headers={
            "User-Agent": "bug-bounty-mcp/0.1 low-risk cors observation",
            "Origin": test_origin,
        },
    ) as client:
        response = client.get(url)

    headers = dict(response.headers)
    normalized_headers = _normalize_headers(headers)

    content_type = response.headers.get("content-type", "")
    title = None

    if "text/html" in content_type:
        title = _extract_title(response.text[:50000])

    acao = normalized_headers.get("access-control-allow-origin")
    acac = normalized_headers.get("access-control-allow-credentials")

    origin_reflected = False
    if acao and str(acao).strip().lower() == test_origin.lower():
        origin_reflected = True

    return {
        "target": target,
        "url": str(response.url),
        "blocked": False,
        "status_code": response.status_code,
        "final_url": str(response.url),
        "redirect_history": [str(history.url) for history in response.history],
        "headers": headers,
        "cors_headers": {
            "access-control-allow-origin": acao,
            "access-control-allow-credentials": acac,
            "access-control-allow-methods": normalized_headers.get("access-control-allow-methods"),
            "access-control-allow-headers": normalized_headers.get("access-control-allow-headers"),
            "access-control-expose-headers": normalized_headers.get("access-control-expose-headers"),
            "vary": normalized_headers.get("vary"),
        },
        "origin_tested": test_origin,
        "origin_reflected": origin_reflected,
        "content_type": content_type,
        "title": title,
        "body_size": len(response.content),
    }


def _safe_cors_observation_request(target: str, url: str, test_origin: str) -> tuple[dict, bool]:
    """
    Normalize one CORS observation helper call into a safe result dictionary.

    Exceptions and malformed helper results become request_error-style metadata
    instead of crashing the workflow. The second return value indicates whether
    a request helper was attempted so request accounting remains auditable.
    """
    try:
        result = _cors_observation_request(target, url, test_origin)
    except Exception as error:
        return _safe_error_result(target, url, test_origin, f"CORS observation helper raised exception: {error}"), True

    if not isinstance(result, dict):
        return _safe_error_result(target, url, test_origin, "CORS observation helper returned a non-dict result."), True

    return result, True


def _observation(target: str, cors_result: dict, status: str, error: str | None = None) -> dict:
    safe_result = _safe_cors_result_for_output(cors_result)
    observation = base_http_observation(
        target,
        {
            "status_code": safe_result.get("status_code"),
            "content_type": safe_result.get("content_type"),
            "body_size": safe_result.get("body_size"),
            "headers": safe_result.get("headers"),
            "error": safe_result.get("error"),
        },
        status,
        error=error if error is not None else safe_result.get("error"),
    )
    observation.update(
        {
            "final_url": safe_result.get("final_url"),
            "origin_tested": safe_result.get("origin_tested"),
            "origin_reflected": safe_result.get("origin_reflected"),
            "cors_headers": safe_result.get("cors_headers", {}),
        }
    )
    return observation


def _summary(requests_sent: int, status: str, cors_result: dict | None = None) -> dict:
    safe_result = _safe_cors_result_for_output(cors_result if isinstance(cors_result, dict) else {})
    return {
        "requests_sent": requests_sent,
        "status": status,
        "max_requests": 1,
        "status_code": safe_result.get("status_code"),
        "final_url": safe_result.get("final_url"),
        "origin_tested": safe_result.get("origin_tested"),
        "origin_reflected": safe_result.get("origin_reflected"),
        "cors_headers": safe_result.get("cors_headers", {}),
        "error": safe_result.get("error"),
    }


def _classify_endpoint(target: str, cors_result: dict) -> dict:
    probe_like_result = {
        "title": cors_result.get("title"),
        "content_type": get_content_type(cors_result),
        "final_url": cors_result.get("final_url") or cors_result.get("url") or target,
        "status_code": cors_result.get("status_code"),
    }

    if classify_endpoint is not None:
        try:
            log_event(f"workflow: starting endpoint classification for cors target={target}")
            classification = classify_endpoint(probe_like_result)

            log_event(
                f"workflow: endpoint classified for cors target={target} "
                f"classification={classification.get('classification')} "
                f"confidence={classification.get('confidence')}"
            )
            return classification
        except Exception as error:
            log_event(
                f"workflow: endpoint classification error for cors target={target} "
                f"error={str(error)}"
            )
            return {
                "classification": "unknown",
                "confidence": "low",
                "reason": f"classifier_error: {str(error)}",
            }

    log_event(f"workflow: endpoint classifier unavailable for cors target={target}")
    return {
        "classification": "unknown",
        "confidence": "low",
        "reason": "endpoint_classifier is not available.",
    }


def safe_cors_observation_workflow(
    target: str,
    test_origin: str = DEFAULT_TEST_ORIGIN,
) -> dict:
    """
    Safely perform one scoped CORS observation workflow.

    Workflow:
    1. Check scope first.
    2. Stop if the target is out of scope.
    3. Send exactly one low-risk GET request with a harmless Origin header.
    4. Observe CORS response headers.
    5. Classify the endpoint if endpoint_classifier is available.
    6. Validate CORS behavior conservatively.
    7. Save the result as an observation or candidate_finding.
    8. Return a concise summary.

    Safety:
    - No fuzzing.
    - No brute force.
    - No exploitation.
    - No crawling.
    - No credentialed request, cookies, tokens, credentials, or session.
    - No form submission or state-changing action.
    - Does not save cookies, tokens, secrets, personal data, payment data, or
      complete response bodies.
    - Exactly one HTTP request.
    """

    safe_origin = _safe_test_origin(test_origin)
    log_event(
        f"tool called: tool_safe_cors_observation_workflow "
        f"target={target} test_origin={safe_origin}"
    )

    # Scope is checked before the only possible external request.
    log_event(f"workflow: cors checking scope target={target}")
    scope = check_scope(target)

    log_event(
        f"workflow: cors scope result target={target} "
        f"in_scope={scope.get('in_scope')} "
        f"hostname={scope.get('hostname')} "
        f"scan_level={scope.get('allowed_scan_level')}"
    )

    if not scope.get("in_scope"):
        log_event(f"workflow: cors blocked out-of-scope target={target}")

        return build_workflow_result(
            target=target,
            stopped=True,
            reason="Target is not in scope.",
            scope=scope,
            observations=[],
            inventory_candidates=[],
            summary=_summary(0, "blocked", {"origin_tested": safe_origin}),
            safety=_safety(0, scan_level="blocked"),
        )

    url = _normalize_url(target)

    log_event(
        f"workflow: starting cors observation request "
        f"target={target} url={url}"
    )
    cors_result, helper_called = _safe_cors_observation_request(target, url, safe_origin)
    requests_sent = 1 if helper_called and not cors_result.get("blocked") else 0
    safe_cors_result = _safe_cors_result_for_output(cors_result)

    log_event(
        f"workflow: cors observation completed target={target} "
        f"status={cors_result.get('status_code')} "
        f"acao={safe_cors_result.get('cors_headers', {}).get('access-control-allow-origin')} "
        f"acac={safe_cors_result.get('cors_headers', {}).get('access-control-allow-credentials')} "
        f"origin_reflected={safe_cors_result.get('origin_reflected')}"
    )

    classification = _classify_endpoint(target, safe_cors_result)

    log_event(f"workflow: starting cors validation target={target}")
    try:
        validation = validate_cors(safe_cors_result, classification)
    except Exception as error:
        validation = {
            "status": "needs_manual_validation",
            "severity": "info",
            "confidence": "low",
            "should_report": False,
            "reason": f"validator_error: {str(error)}",
            "false_positive_notes": ["Validation failed and requires manual review."],
        }

    log_event(
        f"workflow: cors validation completed target={target} "
        f"status={validation.get('status')} "
        f"severity={validation.get('severity')} "
        f"confidence={validation.get('confidence')} "
        f"should_report={validation.get('should_report')}"
    )

    cors_headers = safe_cors_result.get("cors_headers", {})

    if safe_cors_result.get("error"):
        finding_type = "observation"
        title = "CORS observation failed"
        evidence_summary = (
            f"CORS observation failed for {target}. "
            f"Error: {safe_cors_result.get('error')}. "
            f"Validator reason: {validation.get('reason')}"
        )
    elif validation.get("status") == "candidate_finding":
        finding_type = "candidate_finding"
        title = "Potential CORS misconfiguration candidate"
        evidence_summary = (
            f"CORS observation for {target}. "
            f"Tested Origin: {safe_origin}. "
            f"ACAO: {cors_headers.get('access-control-allow-origin')}. "
            f"ACAC: {cors_headers.get('access-control-allow-credentials')}. "
            f"Origin reflected: {safe_cors_result.get('origin_reflected')}. "
            f"Endpoint classification: {classification.get('classification')} "
            f"({classification.get('confidence')}). "
            f"Validator reason: {validation.get('reason')}"
        )
    else:
        finding_type = "observation"
        title = "CORS observation"
        evidence_summary = (
            f"CORS observation for {target}. "
            f"Tested Origin: {safe_origin}. "
            f"ACAO: {cors_headers.get('access-control-allow-origin')}. "
            f"ACAC: {cors_headers.get('access-control-allow-credentials')}. "
            f"Origin reflected: {safe_cors_result.get('origin_reflected')}. "
            f"Endpoint classification: {classification.get('classification')} "
            f"({classification.get('confidence')}). "
            f"Validator reason: {validation.get('reason')}"
        )

    finding = {
        "type": finding_type,
        "title": title,
        "target": target,
        "category": "cors",
        "vulnerability_category": "cors",
        "endpoint_classification": classification,
        "severity": validation.get("severity", "info"),
        "confidence": validation.get("confidence", "medium"),
        "status": validation.get("status", "observation"),
        "origin_tested": safe_origin,
        "origin_reflected": safe_cors_result.get("origin_reflected", False),
        "cors_headers": cors_headers,
        "evidence_summary": evidence_summary,
        "validator_result": validation,
        "next_step": (
            "Manually validate with an authorized test account and a non-destructive endpoint only if the program policy allows it. "
            "Do not report CORS behavior unless practical cross-origin sensitive data access is confirmed."
        ),
    }

    log_event(
        f"workflow: saving cors result target={target} "
        f"type={finding_type} severity={finding.get('severity')}"
    )

    saved = save_finding(finding)

    log_event(
        f"workflow: cors result saved target={target} "
        f"saved={saved.get('saved')} path={saved.get('path')}"
    )

    cors_summary = {
        "status_code": safe_cors_result.get("status_code"),
        "final_url": safe_cors_result.get("final_url"),
        "origin_tested": safe_origin,
        "origin_reflected": safe_cors_result.get("origin_reflected"),
        "cors_headers": cors_headers,
        "error": safe_cors_result.get("error"),
    }

    log_event(
        f"workflow: completed tool_safe_cors_observation_workflow "
        f"target={target} requests_sent=1 "
        f"status={validation.get('status')} "
        f"severity={validation.get('severity')}"
    )

    return build_workflow_result(
        target=target,
        stopped=False,
        scope=scope,
        observations=[_observation(target, safe_cors_result, "request_error" if safe_cors_result.get("error") else "observed")],
        inventory_candidates=[],
        errors=[safe_cors_result.get("error")] if safe_cors_result.get("error") else [],
        summary=_summary(requests_sent, "error" if safe_cors_result.get("error") else "completed", safe_cors_result),
        safety=_safety(requests_sent),
        endpoint_classification=classification,
        cors_summary=cors_summary,
        validator_result=validation,
        saved_result=saved,
    )
