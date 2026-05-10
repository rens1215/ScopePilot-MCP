import httpx

from tools.scope_guard import check_scope
from tools.storage import save_finding
from tools.logger import log_event

from validators.cors_validator import validate_cors

try:
    from tools.endpoint_classifier import classify_endpoint
except ImportError:
    classify_endpoint = None


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


def _normalize_headers(headers: dict) -> dict:
    return {
        str(k).lower(): v
        for k, v in headers.items()
    }


def safe_cors_observation_workflow(
    target: str,
    test_origin: str = "https://example-attacker.invalid"
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
    - No credentialed request.
    - No cookies or tokens.
    - Exactly one HTTP request.
    """

    log_event(
        f"tool called: tool_safe_cors_observation_workflow "
        f"target={target} test_origin={test_origin}"
    )

    # 1. Scope check
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
                "crawling": False,
                "credentialed_request": False
            }
        }

    url = _normalize_url(target)

    # 2. One low-risk CORS observation request
    try:
        log_event(
            f"workflow: starting cors observation request "
            f"target={target} url={url}"
        )

        with httpx.Client(
            follow_redirects=True,
            timeout=10.0,
            headers={
                "User-Agent": "bug-bounty-mcp/0.1 low-risk cors observation",
                "Origin": test_origin
            }
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

        cors_result = {
            "target": target,
            "url": str(response.url),
            "blocked": False,
            "status_code": response.status_code,
            "final_url": str(response.url),
            "redirect_history": [str(r.url) for r in response.history],
            "headers": headers,
            "cors_headers": {
                "access-control-allow-origin": acao,
                "access-control-allow-credentials": acac,
                "access-control-allow-methods": normalized_headers.get("access-control-allow-methods"),
                "access-control-allow-headers": normalized_headers.get("access-control-allow-headers"),
                "access-control-expose-headers": normalized_headers.get("access-control-expose-headers"),
                "vary": normalized_headers.get("vary")
            },
            "origin_tested": test_origin,
            "origin_reflected": origin_reflected,
            "content_type": content_type,
            "title": title,
            "body_size": len(response.content)
        }

        log_event(
            f"workflow: cors observation completed target={target} "
            f"status={response.status_code} "
            f"acao={acao} acac={acac} "
            f"origin_reflected={origin_reflected}"
        )

    except Exception as e:
        log_event(
            f"workflow: cors observation error target={target} "
            f"error={str(e)}"
        )

        cors_result = {
            "target": target,
            "url": url,
            "blocked": False,
            "error": str(e),
            "origin_tested": test_origin,
            "origin_reflected": False,
            "headers": {},
            "cors_headers": {}
        }

    # 3. Endpoint classification
    probe_like_result = {
        "title": cors_result.get("title"),
        "content_type": cors_result.get("content_type"),
        "final_url": cors_result.get("final_url") or cors_result.get("url") or target,
        "status_code": cors_result.get("status_code")
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
        except Exception as e:
            classification = {
                "classification": "unknown",
                "confidence": "low",
                "reason": f"classifier_error: {str(e)}"
            }

            log_event(
                f"workflow: endpoint classification error for cors target={target} "
                f"error={str(e)}"
            )
    else:
        classification = {
            "classification": "unknown",
            "confidence": "low",
            "reason": "endpoint_classifier is not available."
        }

        log_event(f"workflow: endpoint classifier unavailable for cors target={target}")

    # 4. CORS validation
    log_event(f"workflow: starting cors validation target={target}")
    validation = validate_cors(cors_result, classification)

    log_event(
        f"workflow: cors validation completed target={target} "
        f"status={validation.get('status')} "
        f"severity={validation.get('severity')} "
        f"confidence={validation.get('confidence')} "
        f"should_report={validation.get('should_report')}"
    )

    # 5. Save observation / candidate
    cors_headers = cors_result.get("cors_headers", {})

    if cors_result.get("error"):
        finding_type = "observation"
        title = "CORS observation failed"
        evidence_summary = (
            f"CORS observation failed for {target}. "
            f"Error: {cors_result.get('error')}. "
            f"Validator reason: {validation.get('reason')}"
        )
    elif validation.get("status") == "candidate_finding":
        finding_type = "candidate_finding"
        title = "Potential CORS misconfiguration candidate"
        evidence_summary = (
            f"CORS observation for {target}. "
            f"Tested Origin: {test_origin}. "
            f"ACAO: {cors_headers.get('access-control-allow-origin')}. "
            f"ACAC: {cors_headers.get('access-control-allow-credentials')}. "
            f"Origin reflected: {cors_result.get('origin_reflected')}. "
            f"Endpoint classification: {classification.get('classification')} "
            f"({classification.get('confidence')}). "
            f"Validator reason: {validation.get('reason')}"
        )
    else:
        finding_type = "observation"
        title = "CORS observation"
        evidence_summary = (
            f"CORS observation for {target}. "
            f"Tested Origin: {test_origin}. "
            f"ACAO: {cors_headers.get('access-control-allow-origin')}. "
            f"ACAC: {cors_headers.get('access-control-allow-credentials')}. "
            f"Origin reflected: {cors_result.get('origin_reflected')}. "
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
        "origin_tested": test_origin,
        "origin_reflected": cors_result.get("origin_reflected", False),
        "cors_headers": cors_headers,
        "evidence_summary": evidence_summary,
        "validator_result": validation,
        "next_step": (
            "Manually validate with an authorized test account and a non-destructive endpoint only if the program policy allows it. "
            "Do not report CORS behavior unless practical cross-origin sensitive data access is confirmed."
        )
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

    # 6. Return result
    result = {
        "target": target,
        "scope": scope,
        "endpoint_classification": classification,
        "cors_summary": {
            "status_code": cors_result.get("status_code"),
            "final_url": cors_result.get("final_url"),
            "origin_tested": test_origin,
            "origin_reflected": cors_result.get("origin_reflected"),
            "cors_headers": cors_headers,
            "error": cors_result.get("error")
        },
        "validator_result": validation,
        "saved_result": saved,
        "safety": {
            "requests_sent": 1 if not cors_result.get("error") else 1,
            "scan_level": "low-risk",
            "fuzzing": False,
            "bruteforce": False,
            "exploitation": False,
            "crawling": False,
            "credentialed_request": False
        }
    }

    log_event(
        f"workflow: completed tool_safe_cors_observation_workflow "
        f"target={target} requests_sent=1 "
        f"status={validation.get('status')} "
        f"severity={validation.get('severity')}"
    )

    return result