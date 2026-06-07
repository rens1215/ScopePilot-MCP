from tools.http_result_utils import base_http_observation, get_content_type, headers_summary
from tools.logger import log_event
from tools.result_schema import build_workflow_result
from tools.safety_metadata import build_safety_metadata
from tools.scope_guard import check_scope
from tools.storage import save_finding

from validators.header_validator import validate_security_headers

try:
    from tools.security_headers import security_headers_check
except ImportError:
    security_headers_check = None

try:
    from tools.endpoint_classifier import classify_endpoint
except ImportError:
    classify_endpoint = None


SAFE_SECURITY_HEADER_NAMES = {
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
}

SENSITIVE_HEADER_MARKERS = {
    "cookie",
    "authorization",
    "token",
    "secret",
    "api-key",
    "apikey",
}


def _safety(requests_sent: int, scan_level: str = "low-risk") -> dict:
    return build_safety_metadata(requests_sent=requests_sent, scan_level=scan_level)


def _is_sensitive_header_name(header_name: str) -> bool:
    lowered = str(header_name or "").lower()
    return any(marker in lowered for marker in SENSITIVE_HEADER_MARKERS)


def _safe_present_headers(present: dict | None) -> dict:
    """
    Keep only security-header metadata that is safe to store.

    The low-level checker normally returns only recommended security headers.
    This fail-closed filter prevents cookies, authorization material, token-like
    headers, or secret-like headers from being persisted if a malformed helper
    result ever includes them.
    """
    if not isinstance(present, dict):
        return {}

    safe = {}
    for key, value in present.items():
        lowered = str(key).lower()
        if lowered not in SAFE_SECURITY_HEADER_NAMES:
            continue
        if _is_sensitive_header_name(lowered):
            continue
        safe[lowered] = value

    return safe


def _safe_missing_headers(missing) -> list:
    if not isinstance(missing, list):
        return []

    safe = []
    for header in missing:
        lowered = str(header).lower()
        if lowered in SAFE_SECURITY_HEADER_NAMES and not _is_sensitive_header_name(lowered):
            safe.append(lowered)

    return safe


def _safe_header_result_for_output(header_result: dict) -> dict:
    """
    Build a safe, output-oriented copy of security header metadata.

    This intentionally excludes raw probe bodies, cookies, tokens, secrets,
    personal data, payment data, and non-security headers.
    """
    probe = header_result.get("probe") if isinstance(header_result.get("probe"), dict) else {}
    return {
        "target": header_result.get("target"),
        "url": header_result.get("url"),
        "status_code": header_result.get("status_code"),
        "blocked": bool(header_result.get("blocked")),
        "present": _safe_present_headers(header_result.get("present")),
        "missing": _safe_missing_headers(header_result.get("missing")),
        "severity": header_result.get("severity"),
        "note": header_result.get("note"),
        "error": header_result.get("error"),
        "probe": {
            "title": probe.get("title"),
            "content_type": get_content_type(probe),
            "body_size": probe.get("body_size"),
            "headers_summary": headers_summary(probe.get("headers")),
        },
    }


def _safe_check_error(target: str, error: str) -> dict:
    return {
        "target": target,
        "blocked": False,
        "error": error,
        "present": {},
        "missing": [],
        "severity": "info",
        "probe": {},
    }


def _safe_security_headers_check(target: str) -> tuple[dict, bool]:
    """
    Call security_headers_check once and normalize malformed failures.

    The workflow preserves its one-request budget. This helper does not crawl,
    fuzz, brute force, exploit, submit forms, use credentials, or perform
    state-changing actions. Exceptions and non-dict results become structured
    error metadata instead of crashing the workflow.
    """
    if security_headers_check is None:
        return _safe_check_error(target, "security_headers_check helper is unavailable."), False

    try:
        result = security_headers_check(target)
    except Exception as error:
        return _safe_check_error(target, f"security_headers_check raised exception: {error}"), True

    if not isinstance(result, dict):
        return _safe_check_error(target, "security_headers_check returned a non-dict result."), True

    return result, True


def _observation(target: str, header_result: dict, status: str, error: str | None = None) -> dict:
    probe = header_result.get("probe") if isinstance(header_result.get("probe"), dict) else {}
    observation = base_http_observation(target, probe, status, error=error if error is not None else header_result.get("error"))
    observation.update(
        {
            "status_code": header_result.get("status_code", observation.get("status_code")),
            "url": header_result.get("url", observation.get("url")),
            "missing_headers": _safe_missing_headers(header_result.get("missing")),
            "present_headers": _safe_present_headers(header_result.get("present")),
            "severity": header_result.get("severity"),
        }
    )
    return observation


def _summary(requests_sent: int, status: str, header_result: dict | None = None) -> dict:
    safe_result = _safe_header_result_for_output(header_result if isinstance(header_result, dict) else {})
    return {
        "requests_sent": requests_sent,
        "status": status,
        "max_requests": 1,
        "status_code": safe_result.get("status_code"),
        "url": safe_result.get("url"),
        "missing_headers": safe_result.get("missing", []),
        "present_headers": safe_result.get("present", {}),
        "missing_count": len(safe_result.get("missing", [])),
        "severity": safe_result.get("severity"),
    }


def _classify_endpoint(target: str, header_result: dict) -> dict:
    probe = header_result.get("probe") if isinstance(header_result.get("probe"), dict) else {}
    probe_like_result = {
        "title": probe.get("title"),
        "content_type": get_content_type(probe),
        "final_url": header_result.get("url") or target,
        "status_code": header_result.get("status_code"),
    }

    if classify_endpoint is not None:
        try:
            log_event(f"workflow: starting endpoint classification for headers target={target}")
            classification = classify_endpoint(probe_like_result)

            log_event(
                f"workflow: endpoint classified for headers target={target} "
                f"classification={classification.get('classification')} "
                f"confidence={classification.get('confidence')}"
            )
            return classification
        except Exception as error:
            log_event(
                f"workflow: endpoint classification error for headers target={target} "
                f"error={str(error)}"
            )
            return {
                "classification": "unknown",
                "confidence": "low",
                "reason": f"classifier_error: {str(error)}",
            }

    log_event(f"workflow: endpoint classifier unavailable for headers target={target}")
    return {
        "classification": "unknown",
        "confidence": "low",
        "reason": "endpoint_classifier is not available.",
    }


def safe_security_headers_workflow(target: str) -> dict:
    """
    Safely perform one scoped security headers workflow.

    Workflow:
    1. Check scope first.
    2. Stop if the target is out of scope.
    3. Perform one low-risk security headers check if in scope.
    4. Classify the endpoint if endpoint_classifier is available.
    5. Validate missing headers with conservative false-positive-aware logic.
    6. Save the result as an observation or candidate_finding.
    7. Return a concise summary.

    Safety:
    - No fuzzing.
    - No brute force.
    - No exploitation.
    - No crawling.
    - No credentials, form submission, or state-changing action.
    - Does not save cookies, tokens, secrets, personal data, payment data, or
      complete response bodies.
    - Uses one low-risk HTTP request through security_headers_check().
    """

    log_event(f"tool called: tool_safe_security_headers_workflow target={target}")

    # Scope is checked before the only possible external request.
    log_event(f"workflow: security_headers checking scope target={target}")
    scope = check_scope(target)

    log_event(
        f"workflow: security_headers scope result target={target} "
        f"in_scope={scope.get('in_scope')} "
        f"hostname={scope.get('hostname')} "
        f"scan_level={scope.get('allowed_scan_level')}"
    )

    if not scope.get("in_scope"):
        log_event(f"workflow: security_headers blocked out-of-scope target={target}")

        return build_workflow_result(
            target=target,
            stopped=True,
            reason="Target is not in scope.",
            scope=scope,
            observations=[],
            inventory_candidates=[],
            summary=_summary(0, "blocked"),
            safety=_safety(0, scan_level="blocked"),
        )

    log_event(f"workflow: starting security_headers_check target={target}")
    header_result, helper_called = _safe_security_headers_check(target)
    requests_sent = 1 if helper_called and not header_result.get("blocked") else 0
    safe_header_result = _safe_header_result_for_output(header_result)

    log_event(
        f"workflow: security_headers_check completed target={target} "
        f"blocked={header_result.get('blocked')} "
        f"status={header_result.get('status_code')} "
        f"severity={header_result.get('severity')} "
        f"missing_count={len(header_result.get('missing', [])) if isinstance(header_result.get('missing'), list) else 0} "
        f"error={header_result.get('error')}"
    )

    if header_result.get("blocked"):
        log_event(f"workflow: security_headers_check blocked by scope guard target={target}")

        return build_workflow_result(
            target=target,
            stopped=True,
            reason="Security headers check was blocked by scope guard.",
            scope=header_result.get("scope"),
            observations=[_observation(target, header_result, "blocked")],
            inventory_candidates=[],
            summary=_summary(0, "blocked", header_result),
            safety=_safety(0, scan_level="blocked"),
        )

    classification = _classify_endpoint(target, header_result)

    log_event(f"workflow: starting header validation target={target}")
    try:
        validation = validate_security_headers(safe_header_result, classification)
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
        f"workflow: header validation completed target={target} "
        f"status={validation.get('status')} "
        f"severity={validation.get('severity')} "
        f"confidence={validation.get('confidence')} "
        f"should_report={validation.get('should_report')}"
    )

    if header_result.get("error"):
        finding = {
            "type": "observation",
            "title": "Security headers check failed",
            "target": target,
            "category": "security_header",
            "vulnerability_category": "security_header",
            "endpoint_classification": classification,
            "severity": validation.get("severity", "info"),
            "confidence": validation.get("confidence", "low"),
            "status": validation.get("status", "needs_manual_validation"),
            "evidence_summary": header_result.get("error"),
            "validator_result": validation,
            "next_step": "Manually verify whether the target is reachable and whether headers can be checked.",
        }

        log_event(f"workflow: saving security header error observation target={target}")
        saved = save_finding(finding)

        log_event(
            f"workflow: security header error observation saved target={target} "
            f"saved={saved.get('saved')} path={saved.get('path')}"
        )

        return build_workflow_result(
            target=target,
            stopped=False,
            reason="Security headers check failed.",
            scope=scope,
            observations=[_observation(target, header_result, "request_error")],
            inventory_candidates=[],
            errors=[header_result.get("error")],
            summary=_summary(requests_sent, "error", header_result),
            safety=_safety(requests_sent),
            status="error",
            endpoint_classification=classification,
            validator_result=validation,
            error=header_result.get("error"),
            saved_observation=saved,
        )

    missing_headers = safe_header_result.get("missing", [])
    present_headers = safe_header_result.get("present", {})

    if validation.get("status") == "candidate_finding":
        finding_type = "candidate_finding"
        title = "Potential security header hardening issue"
    else:
        finding_type = "observation"
        title = "Security headers observation"

    evidence_summary = (
        f"Security headers checked for {target}. "
        f"Missing headers: {missing_headers}. "
        f"Present recommended headers: {list(present_headers.keys())}. "
        f"Endpoint classification: {classification.get('classification')} "
        f"({classification.get('confidence')}). "
        f"Validator reason: {validation.get('reason')}"
    )

    finding = {
        "type": finding_type,
        "title": title,
        "target": target,
        "category": "security_header",
        "vulnerability_category": "security_header",
        "endpoint_classification": classification,
        "severity": validation.get("severity", "info"),
        "confidence": validation.get("confidence", "medium"),
        "status": validation.get("status", "observation"),
        "missing_headers": missing_headers,
        "present_headers": present_headers,
        "evidence_summary": evidence_summary,
        "validator_result": validation,
        "next_step": (
            "Manually validate whether the missing headers create practical impact. "
            "Do not report missing headers alone unless the bug bounty policy accepts hardening issues."
        ),
    }

    log_event(
        f"workflow: saving security header result target={target} "
        f"type={finding_type} severity={finding.get('severity')}"
    )

    saved = save_finding(finding)

    log_event(
        f"workflow: security header result saved target={target} "
        f"saved={saved.get('saved')} path={saved.get('path')}"
    )

    header_summary = {
        "status_code": safe_header_result.get("status_code"),
        "url": safe_header_result.get("url"),
        "missing_headers": missing_headers,
        "present_headers": present_headers,
        "missing_count": len(missing_headers) if isinstance(missing_headers, list) else 0,
    }

    log_event(
        f"workflow: completed tool_safe_security_headers_workflow "
        f"target={target} requests_sent=1 "
        f"status={validation.get('status')} "
        f"severity={validation.get('severity')}"
    )

    return build_workflow_result(
        target=target,
        stopped=False,
        scope=scope,
        observations=[_observation(target, header_result, "observed")],
        inventory_candidates=[],
        summary=_summary(requests_sent, "completed", header_result),
        safety=_safety(requests_sent),
        endpoint_classification=classification,
        header_summary=header_summary,
        validator_result=validation,
        saved_result=saved,
    )
