from tools.scope_guard import check_scope
from tools.storage import save_finding
from tools.logger import log_event
from tools.priority_scorer import score_workflow_priority
from tools.http_result_utils import get_content_type, headers_summary
from tools.result_schema import build_workflow_result
from tools.safety_metadata import build_safety_metadata

from workflows.safe_http_probe_workflow import safe_http_probe_workflow
from workflows.safe_security_headers_workflow import safe_security_headers_workflow
from workflows.safe_cors_observation_workflow import safe_cors_observation_workflow


EXPECTED_REQUEST_BUDGET = 3

SENSITIVE_MARKERS = {
    "cookie",
    "authorization",
    "token",
    "secret",
    "api-key",
    "apikey",
    "personal_data",
    "payment_data",
}

SAFE_SECURITY_HEADER_NAMES = {
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
}

SAFE_CORS_HEADER_NAMES = {
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "vary",
}


def _safety(requests_sent: int, scan_level: str = "low-risk") -> dict:
    return build_safety_metadata(requests_sent=requests_sent, scan_level=scan_level)


def _contains_sensitive_marker(value) -> bool:
    lowered = str(value or "").lower()
    return any(marker in lowered for marker in SENSITIVE_MARKERS)


def _safe_scalar(value):
    if _contains_sensitive_marker(value):
        return None
    return value


def _safe_validator_result(value) -> dict:
    """
    Keep validator metadata only when it is dictionary-shaped and non-sensitive.

    Passive recon is a summary workflow, not a validator. This defensive copy
    prevents malformed or unexpectedly sensitive child workflow output from
    being propagated into saved findings.
    """
    if not isinstance(value, dict):
        return {}

    safe = {}
    for key in (
        "status",
        "severity",
        "confidence",
        "should_report",
        "reason",
        "false_positive_notes",
    ):
        if key not in value:
            continue
        safe_value = value.get(key)
        if isinstance(safe_value, list):
            safe[key] = [_safe_scalar(item) for item in safe_value if _safe_scalar(item) is not None]
        else:
            safe[key] = _safe_scalar(safe_value)

    return safe


def _safe_security_headers(headers) -> dict:
    if not isinstance(headers, dict):
        return {}

    safe = {}
    for key, value in headers.items():
        lowered = str(key).lower()
        if lowered not in SAFE_SECURITY_HEADER_NAMES:
            continue
        if _contains_sensitive_marker(lowered) or _contains_sensitive_marker(value):
            continue
        safe[lowered] = value

    return safe


def _safe_missing_headers(headers) -> list:
    if not isinstance(headers, list):
        return []

    safe = []
    for header in headers:
        lowered = str(header).lower()
        if lowered in SAFE_SECURITY_HEADER_NAMES and not _contains_sensitive_marker(lowered):
            safe.append(lowered)

    return safe


def _safe_cors_headers(headers) -> dict:
    if not isinstance(headers, dict):
        return {}

    safe = {}
    for key in SAFE_CORS_HEADER_NAMES:
        value = headers.get(key)
        if value is None:
            continue
        if _contains_sensitive_marker(key) or _contains_sensitive_marker(value):
            continue
        safe[key] = value

    return safe


def _safe_probe_summary(result: dict) -> dict:
    summary = result.get("probe_summary") if isinstance(result.get("probe_summary"), dict) else {}
    return {
        "status_code": summary.get("status_code"),
        "final_url": summary.get("final_url"),
        "redirect_history": list(summary.get("redirect_history", []))
        if isinstance(summary.get("redirect_history"), list)
        else [],
        "title": _safe_scalar(summary.get("title")),
        "content_type": get_content_type(summary) or _safe_scalar(summary.get("content_type")),
        "body_size": summary.get("body_size"),
        "headers_summary": headers_summary(summary.get("headers_summary") or summary.get("headers")),
        "error": _safe_scalar(result.get("probe_error") or result.get("error")),
    }


def _safe_header_summary(result: dict) -> dict:
    summary = result.get("header_summary") if isinstance(result.get("header_summary"), dict) else {}
    missing_headers = _safe_missing_headers(summary.get("missing_headers"))
    return {
        "status_code": summary.get("status_code"),
        "url": summary.get("url"),
        "missing_headers": missing_headers,
        "present_headers": _safe_security_headers(summary.get("present_headers")),
        "missing_count": len(missing_headers),
        "validator_result": _safe_validator_result(result.get("validator_result")),
        "error": _safe_scalar(result.get("error")),
    }


def _safe_cors_summary(result: dict) -> dict:
    summary = result.get("cors_summary") if isinstance(result.get("cors_summary"), dict) else {}
    return {
        "status_code": summary.get("status_code"),
        "final_url": summary.get("final_url"),
        "origin_tested": _safe_scalar(summary.get("origin_tested")),
        "origin_reflected": bool(summary.get("origin_reflected", False)),
        "cors_headers": _safe_cors_headers(summary.get("cors_headers")),
        "validator_result": _safe_validator_result(result.get("validator_result")),
        "error": _safe_scalar(summary.get("error") or result.get("error")),
    }


def _safe_endpoint_classification(value: dict) -> dict:
    if not isinstance(value, dict):
        return {
            "classification": "unknown",
            "confidence": "low",
            "reason": "No endpoint classification found in workflow results.",
        }

    return {
        "classification": _safe_scalar(value.get("classification")) or "unknown",
        "confidence": _safe_scalar(value.get("confidence")) or "low",
        "reason": _safe_scalar(value.get("reason")) or "",
    }


def _safe_priority(value: dict) -> dict:
    if not isinstance(value, dict):
        return {
            "priority": "low",
            "score": 0,
            "reasons": ["Priority scorer did not return usable metadata."],
        }

    reasons = value.get("reasons", [])
    if not isinstance(reasons, list):
        reasons = []

    return {
        "priority": _safe_scalar(value.get("priority")) or "low",
        "score": value.get("score", 0),
        "reasons": [_safe_scalar(reason) for reason in reasons if _safe_scalar(reason) is not None],
    }


def _workflow_error_result(workflow_name: str, error: str) -> dict:
    """
    Build a fail-closed child workflow result without executing fallback tools.

    Passive recon must not crash if a child workflow raises or returns malformed
    data. The replacement result records only local error metadata and does not
    send requests, call another workflow, or preserve sensitive response data.
    """
    return {
        "status": "error",
        "error": error,
        "validator_result": {
            "status": "needs_manual_validation",
            "severity": "info",
            "confidence": "low",
            "should_report": False,
            "reason": error,
            "false_positive_notes": [f"{workflow_name} did not return a usable result."],
        },
        "observations": [
            {
                "source": workflow_name,
                "status": "workflow_error",
                "error": error,
            }
        ],
        "safety": _safety(0),
    }


def _run_child_workflow(workflow_name: str, workflow_func, target: str) -> dict:
    """
    Execute one existing child workflow and normalize failure modes.

    This wrapper does not add new request paths or retries. It calls only the
    child workflow that passive recon already used, then converts exceptions or
    non-dict returns into local error observations so the parent workflow can
    fail closed without crashing.
    """
    try:
        result = workflow_func(target)
    except Exception as error:
        return _workflow_error_result(workflow_name, f"{workflow_name} raised exception: {error}")

    if not isinstance(result, dict):
        return _workflow_error_result(workflow_name, f"{workflow_name} returned a non-dict result.")

    return result


def _extract_status(result: dict) -> str:
    if not isinstance(result, dict):
        return "error"
    if result.get("stopped"):
        return "stopped"
    if result.get("status") == "error":
        return "error"
    return "completed"


def _extract_candidate_count(results: list[dict]) -> int:
    count = 0

    for result in results:
        if not isinstance(result, dict):
            continue
        validator = result.get("validator_result", {})
        if isinstance(validator, dict) and validator.get("status") == "candidate_finding":
            count += 1

    return count


def _extract_observation_count(results: list[dict]) -> int:
    count = 0

    for result in results:
        if not isinstance(result, dict):
            continue
        if result.get("stopped"):
            continue

        validator = result.get("validator_result")

        if validator is None:
            count += 1
            continue

        if validator.get("status") in ["observation", "needs_manual_validation"]:
            count += 1

    return count


def _get_endpoint_classification(*results: dict) -> dict:
    for result in results:
        if not isinstance(result, dict):
            continue
        classification = result.get("endpoint_classification")
        if isinstance(classification, dict):
            return _safe_endpoint_classification(classification)

    return _safe_endpoint_classification({
        "classification": "unknown",
        "confidence": "low",
        "reason": "No endpoint classification found in workflow results."
    })


def _collect_child_errors(*results: dict) -> list[dict]:
    errors = []
    for workflow_name, result in results:
        if not isinstance(result, dict):
            errors.append({"source": workflow_name, "error": "Child workflow returned non-dict result."})
            continue

        error = result.get("error") or result.get("probe_error")
        if error:
            errors.append({"source": workflow_name, "error": _safe_scalar(error)})

        for child_error in result.get("errors", []):
            safe_error = child_error if isinstance(child_error, dict) else {"error": child_error}
            errors.append(
                {
                    "source": workflow_name,
                    "error": _safe_scalar(safe_error.get("error") or safe_error),
                }
            )

    return errors


def _observations_for_parent(*results: dict) -> list[dict]:
    observations = []
    for workflow_name, result in results:
        observations.append(
            {
                "source": workflow_name,
                "status": _extract_status(result),
                "error": _safe_scalar(result.get("error") or result.get("probe_error"))
                if isinstance(result, dict)
                else "Child workflow returned non-dict result.",
            }
        )
    return observations


def _safe_score_workflow_priority(endpoint_classification: dict, http_result: dict, security_result: dict, cors_result: dict) -> dict:
    """
    Call the existing priority scorer without letting summary generation crash.

    Priority is triage metadata only. If the scorer fails, the workflow keeps a
    conservative low priority and records the reason instead of changing the
    external request behavior.
    """
    try:
        priority = score_workflow_priority(
            endpoint_classification=endpoint_classification,
            http_result=http_result,
            security_result=security_result,
            cors_result=cors_result
        )
    except Exception as error:
        return _safe_priority({
            "priority": "low",
            "score": 0,
            "reasons": [f"priority_scorer_error: {error}"],
        })

    return _safe_priority(priority if isinstance(priority, dict) else {
        "priority": "low",
        "score": 0,
        "reasons": ["priority_scorer returned a non-dict result."],
    })

def safe_passive_recon_workflow(target: str) -> dict:
    """
    Safely perform a passive / low-risk recon workflow.

    Workflow:
    1. Check scope first.
    2. Stop if the target is out of scope.
    3. Run safe_http_probe_workflow.
    4. Run safe_security_headers_workflow.
    5. Run safe_cors_observation_workflow.
    6. Consolidate results.
    7. Save a summary observation.
    8. Return a concise passive recon summary.

    Safety:
    - Coordinates existing safe child workflows only.
    - Does not add new request paths, retries, crawling, or validation.
    - No fuzzing.
    - No brute force.
    - No exploitation.
    - No crawling.
    - No credentialed requests.
    - No payload injection.
    - No form submission or state-changing action.
    - Does not save cookies, tokens, secrets, personal data, payment data, or
      complete response bodies.
    - Expected total requests: 3
      1 from HTTP probe
      1 from security headers check
      1 from CORS observation
    """

    log_event(f"tool called: tool_safe_passive_recon_workflow target={target}")

    log_event(f"workflow: passive_recon checking scope target={target}")
    scope = check_scope(target)

    log_event(
        f"workflow: passive_recon scope result target={target} "
        f"in_scope={scope.get('in_scope')} "
        f"hostname={scope.get('hostname')} "
        f"scan_level={scope.get('allowed_scan_level')}"
    )

    if not scope.get("in_scope"):
        log_event(f"workflow: passive_recon blocked out-of-scope target={target}")

        return build_workflow_result(
            target=target,
            stopped=True,
            reason="Target is not in scope.",
            scope=scope,
            observations=[],
            inventory_candidates=[],
            summary={},
            safety=_safety(0, scan_level="blocked"),
        )

    # 1. Safe HTTP probe
    log_event(f"workflow: passive_recon starting safe_http_probe_workflow target={target}")
    http_result = _run_child_workflow("http_probe", safe_http_probe_workflow, target)
    log_event(
        f"workflow: passive_recon safe_http_probe_workflow completed "
        f"target={target} status={_extract_status(http_result)}"
    )

    # 2. Safe security headers
    log_event(f"workflow: passive_recon starting safe_security_headers_workflow target={target}")
    security_result = _run_child_workflow("security_headers", safe_security_headers_workflow, target)
    log_event(
        f"workflow: passive_recon safe_security_headers_workflow completed "
        f"target={target} status={_extract_status(security_result)}"
    )

    # 3. Safe CORS observation
    log_event(f"workflow: passive_recon starting safe_cors_observation_workflow target={target}")
    cors_result = _run_child_workflow("cors_observation", safe_cors_observation_workflow, target)
    log_event(
        f"workflow: passive_recon safe_cors_observation_workflow completed "
        f"target={target} status={_extract_status(cors_result)}"
    )

    workflow_results = [
        http_result,
        security_result,
        cors_result
    ]

    endpoint_classification = _get_endpoint_classification(
        http_result,
        security_result,
        cors_result
    )

    candidate_count = _extract_candidate_count(workflow_results)
    observation_count = _extract_observation_count(workflow_results)

    priority = _safe_score_workflow_priority(
        endpoint_classification=endpoint_classification,
        http_result=http_result,
        security_result=security_result,
        cors_result=cors_result
    )

    # Child workflows already sanitize their own outputs, but passive recon is
    # the last aggregation point before storage. Rebuild summaries from a safe
    # allowlist so malformed child output cannot persist secrets or full bodies.
    http_summary = _safe_probe_summary(http_result)
    security_summary = _safe_header_summary(security_result)
    cors_summary = _safe_cors_summary(cors_result)

    recommended_next_steps = []

    if security_result.get("validator_result", {}).get("status") == "candidate_finding":
        recommended_next_steps.append(
            "Manually review whether missing security headers create practical impact before reporting."
        )

    if cors_result.get("validator_result", {}).get("status") == "candidate_finding":
        recommended_next_steps.append(
            "Manually validate CORS behavior with an authorized test account and non-destructive endpoint only if policy allows."
        )

    if endpoint_classification.get("classification") == "frontend":
        recommended_next_steps.append(
            "Consider running a future safe JS endpoint extraction workflow on directly referenced frontend scripts."
        )

    if endpoint_classification.get("classification") == "api":
        recommended_next_steps.append(
            "Prioritize manual review of authentication, authorization, CORS, and response sensitivity."
        )

    if not recommended_next_steps:
        recommended_next_steps.append(
            "No high-priority issue detected. Review observations manually and continue with other low-risk recon workflows if needed."
        )

    consolidated_finding = {
        "type": "observation",
        "title": "Passive recon summary",
        "target": target,
        "category": "passive_recon",
        "vulnerability_category": "recon_summary",
        "endpoint_classification": endpoint_classification,
        "severity": "info",
        "confidence": "high",
        "status": "observation",
        "summary": {
            "http_probe": {
                "status_code": http_summary.get("status_code"),
                "final_url": http_summary.get("final_url"),
                "title": http_summary.get("title"),
                "content_type": http_summary.get("content_type"),
                "body_size": http_summary.get("body_size")
            },
            "security_headers": {
                "missing_headers": security_summary.get("missing_headers"),
                "missing_count": security_summary.get("missing_count"),
                "validator_result": security_summary.get("validator_result")
            },
            "cors": {
                "origin_tested": cors_summary.get("origin_tested"),
                "origin_reflected": cors_summary.get("origin_reflected"),
                "cors_headers": cors_summary.get("cors_headers"),
                "validator_result": cors_summary.get("validator_result")
            },
            "candidate_count": candidate_count,
            "observation_count": observation_count,
            "priority": priority
        },
        "evidence_summary": (
            f"Passive recon completed for {target}. "
            f"Endpoint classification: {endpoint_classification.get('classification')} "
            f"({endpoint_classification.get('confidence')}). "
            f"Candidate findings: {candidate_count}. "
            f"Observations: {observation_count}. "
            f"Priority: {priority.get('priority')}."
        ),
        "next_step": " ".join(recommended_next_steps)
    }

    log_event(f"workflow: passive_recon saving consolidated summary target={target}")
    saved = save_finding(consolidated_finding)

    log_event(
        f"workflow: passive_recon consolidated summary saved target={target} "
        f"saved={saved.get('saved')} path={saved.get('path')}"
    )

    workflow_status = {
        "http_probe": _extract_status(http_result),
        "security_headers": _extract_status(security_result),
        "cors_observation": _extract_status(cors_result)
    }

    summary = {
        "http_probe": http_summary,
        "security_headers": security_summary,
        "cors": cors_summary,
        "candidate_count": candidate_count,
        "observation_count": observation_count,
        "priority": priority,
        "recommended_next_steps": recommended_next_steps
    }

    result = build_workflow_result(
        target=target,
        stopped=False,
        scope=scope,
        observations=_observations_for_parent(
            ("http_probe", http_result),
            ("security_headers", security_result),
            ("cors_observation", cors_result),
        ),
        inventory_candidates=[],
        findings=[],
        errors=_collect_child_errors(
            ("http_probe", http_result),
            ("security_headers", security_result),
            ("cors_observation", cors_result),
        ),
        warnings=[],
        summary=summary,
        safety=_safety(EXPECTED_REQUEST_BUDGET),
        endpoint_classification=endpoint_classification,
        workflow_status=workflow_status,
        saved_summary=saved,
    )

    log_event(
        f"workflow: completed tool_safe_passive_recon_workflow "
        f"target={target} requests_sent={EXPECTED_REQUEST_BUDGET} "
        f"candidate_count={candidate_count} "
        f"priority={priority.get('priority')}"
    )

    return result
