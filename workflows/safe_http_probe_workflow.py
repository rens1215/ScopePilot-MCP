from tools.http_result_utils import base_http_observation, get_content_type, headers_summary, safe_http_probe_call
from tools.logger import log_event
from tools.result_schema import build_workflow_result
from tools.safety_metadata import build_safety_metadata
from tools.scope_guard import check_scope
from tools.storage import save_finding

try:
    from tools.http_probe import http_probe
except ImportError:
    http_probe = None

try:
    from tools.endpoint_classifier import classify_endpoint
except ImportError:
    classify_endpoint = None


def _safety(requests_sent: int, scan_level: str = "low-risk") -> dict:
    return build_safety_metadata(requests_sent=requests_sent, scan_level=scan_level)


def _safe_http_probe(target: str) -> tuple[dict, bool]:
    """
    Call the low-risk HTTP probe helper once and normalize failures.

    This wrapper preserves the workflow's one-request budget. It does not crawl,
    fuzz, brute force, exploit, submit forms, use credentials, or perform
    state-changing actions. Exceptions and malformed probe results become
    request_error metadata instead of crashing the workflow.
    """
    if http_probe is None:
        return {
            "blocked": False,
            "status": "request_error",
            "error": "HTTP probe helper is unavailable.",
        }, False

    return safe_http_probe_call(target, probe_func=http_probe)


def _probe_summary(probe: dict) -> dict:
    """
    Return backward-compatible probe metadata without full response bodies.

    Only safe metadata is copied into workflow output. Sensitive headers such as
    cookies, authorization material, tokens, secrets, and API keys are filtered
    by headers_summary().
    """
    return {
        "status_code": probe.get("status_code"),
        "final_url": probe.get("final_url"),
        "redirect_history": probe.get("redirect_history"),
        "title": probe.get("title"),
        "content_type": get_content_type(probe),
        "body_size": probe.get("body_size"),
        "headers_summary": headers_summary(probe.get("headers")),
    }


def _summary(requests_sent: int, status: str, probe: dict | None = None) -> dict:
    safe_probe = probe if isinstance(probe, dict) else {}
    return {
        "requests_sent": requests_sent,
        "status": status,
        "max_requests": 1,
        "status_code": safe_probe.get("status_code"),
        "final_url": safe_probe.get("final_url"),
        "content_type": get_content_type(safe_probe),
        "body_size": safe_probe.get("body_size"),
    }


def safe_http_probe_workflow(target: str) -> dict:
    """
    Safely perform one scoped HTTP probe workflow.

    Workflow:
    1. Check scope first.
    2. Stop if the target is out of scope.
    3. Perform exactly one low-risk HTTP probe if in scope.
    4. Optionally classify the endpoint if endpoint_classifier is available.
    5. Save the result as an observation.
    6. Return a concise summary.

    Safety:
    - No fuzzing.
    - No brute force.
    - No exploitation.
    - No crawling.
    - No credentials, form submission, or state-changing action.
    - Does not save cookies, tokens, secrets, personal data, payment data, or
      complete response bodies.
    - Exactly one HTTP probe request through http_probe().
    """

    log_event(f"tool called: tool_safe_http_probe_workflow target={target}")

    # Scope is checked before the only possible external request.
    log_event(f"workflow: checking scope target={target}")
    scope = check_scope(target)

    log_event(
        f"workflow: scope result target={target} "
        f"in_scope={scope.get('in_scope')} "
        f"hostname={scope.get('hostname')} "
        f"scan_level={scope.get('allowed_scan_level')}"
    )

    if not scope.get("in_scope"):
        log_event(f"workflow: blocked out-of-scope target={target}")

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

    # The workflow owns a hard one-request budget. _safe_http_probe normalizes
    # helper failures, but it never performs retries or follow-up requests.
    log_event(f"workflow: starting http_probe target={target}")
    probe, helper_called = _safe_http_probe(target)
    requests_sent = 1 if helper_called and not probe.get("blocked") else 0

    log_event(
        f"workflow: http_probe completed target={target} "
        f"blocked={probe.get('blocked')} "
        f"status={probe.get('status_code')} "
        f"final_url={probe.get('final_url')} "
        f"error={probe.get('error')}"
    )

    # Defense-in-depth: http_probe has its own scope guard. Preserve the legacy
    # blocked path and report zero requests when the helper blocks internally.
    if probe.get("blocked"):
        log_event(f"workflow: http_probe blocked by scope guard target={target}")

        return build_workflow_result(
            target=target,
            stopped=True,
            reason="HTTP probe was blocked by scope guard.",
            scope=probe.get("scope"),
            observations=[base_http_observation(target, probe, "blocked")],
            inventory_candidates=[],
            summary=_summary(0, "blocked", probe),
            safety=_safety(0, scan_level="blocked"),
        )

    if probe.get("error"):
        log_event(
            f"workflow: http_probe error target={target} "
            f"error={probe.get('error')}"
        )

        finding = {
            "type": "observation",
            "title": "HTTP probe failed",
            "target": target,
            "category": "http_probe",
            "endpoint_classification": {
                "classification": "unknown",
                "confidence": "low",
                "reason": "HTTP probe failed before classification.",
            },
            "severity": "info",
            "confidence": "low",
            "status": "needs_manual_validation",
            "evidence_summary": probe.get("error"),
            "next_step": "Manually verify whether the target is reachable.",
        }

        log_event(f"workflow: saving error observation target={target}")
        saved = save_finding(finding)

        log_event(
            f"workflow: error observation saved target={target} "
            f"saved={saved.get('saved')} path={saved.get('path')}"
        )

        return build_workflow_result(
            target=target,
            stopped=False,
            reason="HTTP probe failed.",
            scope=scope,
            observations=[base_http_observation(target, probe, "request_error")],
            inventory_candidates=[],
            errors=[probe.get("error")],
            summary=_summary(requests_sent, "error", probe),
            safety=_safety(requests_sent),
            status="error",
            probe_error=probe.get("error"),
            saved_observation=saved,
        )

    if classify_endpoint is not None:
        try:
            log_event(f"workflow: starting endpoint classification target={target}")
            classification = classify_endpoint(probe)

            log_event(
                f"workflow: endpoint classified target={target} "
                f"classification={classification.get('classification')} "
                f"confidence={classification.get('confidence')}"
            )
        except Exception as error:
            classification = {
                "classification": "unknown",
                "confidence": "low",
                "reason": f"classifier_error: {str(error)}",
            }

            log_event(
                f"workflow: endpoint classification error target={target} "
                f"error={str(error)}"
            )
    else:
        classification = {
            "classification": "unknown",
            "confidence": "low",
            "reason": "endpoint_classifier is not available.",
        }

        log_event(f"workflow: endpoint classifier unavailable target={target}")

    finding = {
        "type": "observation",
        "title": "HTTP probe result",
        "target": target,
        "category": "http_probe",
        "endpoint_classification": classification,
        "severity": "info",
        "confidence": "high",
        "status": "observation",
        "evidence_summary": (
            f"HTTP GET returned {probe.get('status_code')}. "
            f"Final URL: {probe.get('final_url')}. "
            f"Title: {probe.get('title')}. "
            f"Content-Type: {get_content_type(probe)}. "
            f"Body size: {probe.get('body_size')} bytes. "
            f"Endpoint classification: {classification.get('classification')} "
            f"({classification.get('confidence')})."
        ),
        "next_step": "Review the target manually or run a specific low-risk validator if needed.",
    }

    log_event(f"workflow: saving observation target={target}")
    saved = save_finding(finding)

    log_event(
        f"workflow: observation saved target={target} "
        f"saved={saved.get('saved')} path={saved.get('path')}"
    )

    log_event(
        f"workflow: completed tool_safe_http_probe_workflow "
        f"target={target} requests_sent=1 "
        f"classification={classification.get('classification')}"
    )

    return build_workflow_result(
        target=target,
        stopped=False,
        scope=scope,
        observations=[base_http_observation(target, probe, "observed")],
        inventory_candidates=[],
        summary=_summary(requests_sent, "completed", probe),
        safety=_safety(requests_sent),
        endpoint_classification=classification,
        probe_summary=_probe_summary(probe),
        saved_observation=saved,
    )
