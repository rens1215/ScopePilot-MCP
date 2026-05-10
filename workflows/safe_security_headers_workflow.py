from tools.scope_guard import check_scope
from tools.security_headers import security_headers_check
from tools.storage import save_finding
from tools.logger import log_event

from validators.header_validator import validate_security_headers

try:
    from tools.endpoint_classifier import classify_endpoint
except ImportError:
    classify_endpoint = None


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
    - Uses one low-risk HTTP request through security_headers_check().
    """

    log_event(f"tool called: tool_safe_security_headers_workflow target={target}")

    # 1. Scope check
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

        return {
            "target": target,
            "stopped": True,
            "reason": "Target is not in scope.",
            "scope": scope,
            "safety": {
                "requests_sent": 0,
                "scan_level": "blocked",
                "fuzzing": False,
                "bruteforce": False,
                "exploitation": False,
                "crawling": False
            }
        }

    # 2. Security headers check
    log_event(f"workflow: starting security_headers_check target={target}")
    header_result = security_headers_check(target)

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

        return {
            "target": target,
            "stopped": True,
            "reason": "Security headers check was blocked by scope guard.",
            "scope": header_result.get("scope"),
            "safety": {
                "requests_sent": 0,
                "scan_level": "blocked",
                "fuzzing": False,
                "bruteforce": False,
                "exploitation": False,
                "crawling": False
            }
        }

    # 3. Endpoint classification
    probe_like_result = {
        "title": header_result.get("probe", {}).get("title"),
        "content_type": header_result.get("probe", {}).get("content_type"),
        "final_url": header_result.get("url") or target,
        "status_code": header_result.get("status_code")
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
        except Exception as e:
            classification = {
                "classification": "unknown",
                "confidence": "low",
                "reason": f"classifier_error: {str(e)}"
            }

            log_event(
                f"workflow: endpoint classification error for headers target={target} "
                f"error={str(e)}"
            )
    else:
        classification = {
            "classification": "unknown",
            "confidence": "low",
            "reason": "endpoint_classifier is not available."
        }

        log_event(f"workflow: endpoint classifier unavailable for headers target={target}")

    # 4. Validator
    log_event(f"workflow: starting header validation target={target}")
    validation = validate_security_headers(header_result, classification)

    log_event(
        f"workflow: header validation completed target={target} "
        f"status={validation.get('status')} "
        f"severity={validation.get('severity')} "
        f"confidence={validation.get('confidence')} "
        f"should_report={validation.get('should_report')}"
    )

    # 5. Error observation
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
            "next_step": "Manually verify whether the target is reachable and whether headers can be checked."
        }

        log_event(f"workflow: saving security header error observation target={target}")
        saved = save_finding(finding)

        log_event(
            f"workflow: security header error observation saved target={target} "
            f"saved={saved.get('saved')} path={saved.get('path')}"
        )

        return {
            "target": target,
            "status": "error",
            "scope": scope,
            "endpoint_classification": classification,
            "validator_result": validation,
            "error": header_result.get("error"),
            "saved_observation": saved,
            "safety": {
                "requests_sent": 1,
                "scan_level": "low-risk",
                "fuzzing": False,
                "bruteforce": False,
                "exploitation": False,
                "crawling": False
            }
        }

    # 6. Normal observation / candidate finding
    missing_headers = header_result.get("missing", [])
    present_headers = header_result.get("present", {})

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
        )
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

    result = {
        "target": target,
        "scope": scope,
        "endpoint_classification": classification,
        "header_summary": {
            "status_code": header_result.get("status_code"),
            "url": header_result.get("url"),
            "missing_headers": missing_headers,
            "present_headers": present_headers,
            "missing_count": len(missing_headers) if isinstance(missing_headers, list) else 0
        },
        "validator_result": validation,
        "saved_result": saved,
        "safety": {
            "requests_sent": 1,
            "scan_level": "low-risk",
            "fuzzing": False,
            "bruteforce": False,
            "exploitation": False,
            "crawling": False
        }
    }

    log_event(
        f"workflow: completed tool_safe_security_headers_workflow "
        f"target={target} requests_sent=1 "
        f"status={validation.get('status')} "
        f"severity={validation.get('severity')}"
    )

    return result