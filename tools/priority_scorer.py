def _safe_get(d: dict, key: str, default=None):
    if not isinstance(d, dict):
        return default
    return d.get(key, default)


def _validator_status(result: dict) -> str:
    validator = _safe_get(result, "validator_result", {})
    return _safe_get(validator, "status", "observation")


def _validator_severity(result: dict) -> str:
    validator = _safe_get(result, "validator_result", {})
    return _safe_get(validator, "severity", "info")


def _validator_confidence(result: dict) -> str:
    validator = _safe_get(result, "validator_result", {})
    return _safe_get(validator, "confidence", "medium")


def _validator_should_report(result: dict) -> bool:
    validator = _safe_get(result, "validator_result", {})
    return bool(_safe_get(validator, "should_report", False))


def _score_severity(severity: str) -> int:
    severity = (severity or "info").lower()

    mapping = {
        "info": 0,
        "low": 10,
        "medium": 25,
        "high": 45,
        "critical": 70
    }

    return mapping.get(severity, 0)


def _score_confidence(confidence: str) -> int:
    confidence = (confidence or "medium").lower()

    mapping = {
        "low": 0,
        "medium": 10,
        "high": 20
    }

    return mapping.get(confidence, 5)


def score_finding_priority(
    finding_type: str,
    vulnerability_category: str,
    endpoint_classification: dict | None = None,
    severity: str = "info",
    confidence: str = "medium",
    status: str = "observation",
    should_report: bool = False
) -> dict:
    """
    Score a single finding or observation for manual review priority.

    This is NOT CVSS severity.
    This score only means:
    - how soon a human should review it
    - how likely it is to be useful for bug bounty triage

    It is intentionally conservative.
    """

    endpoint_classification = endpoint_classification or {
        "classification": "unknown",
        "confidence": "low"
    }

    endpoint_type = endpoint_classification.get("classification", "unknown")

    score = 0
    reasons = []

    # 1. Finding type
    if finding_type == "confirmed_finding":
        score += 50
        reasons.append("Confirmed finding requires immediate manual review.")

    elif finding_type == "candidate_finding":
        score += 30
        reasons.append("Candidate finding deserves manual validation.")

    elif finding_type == "observation":
        score += 5
        reasons.append("Observation has limited priority unless combined with stronger signals.")

    # 2. Status
    if status == "candidate_finding":
        score += 25
        reasons.append("Validator classified this as a candidate finding.")

    elif status == "needs_manual_validation":
        score += 15
        reasons.append("Manual validation is explicitly required.")

    elif status == "confirmed_finding":
        score += 50
        reasons.append("Validator classified this as confirmed.")

    # 3. Severity and confidence
    sev_score = _score_severity(severity)
    conf_score = _score_confidence(confidence)

    score += sev_score
    score += conf_score

    if sev_score > 0:
        reasons.append(f"Severity contributes to priority: {severity}.")

    if conf_score > 0:
        reasons.append(f"Confidence contributes to priority: {confidence}.")

    # 4. Endpoint importance
    if endpoint_type in ["admin_panel", "auth_service"]:
        score += 25
        reasons.append(f"High-value endpoint type: {endpoint_type}.")

    elif endpoint_type == "api":
        score += 20
        reasons.append("API endpoint may be relevant for authorization, CORS, and data exposure review.")

    elif endpoint_type == "graphql":
        score += 20
        reasons.append("GraphQL endpoint may deserve focused manual review.")

    elif endpoint_type == "frontend":
        score += 5
        reasons.append("Frontend endpoint may be relevant for client-side observations.")

    elif endpoint_type in ["static_asset", "cdn"]:
        score -= 15
        reasons.append("Static/CDN content usually has lower security impact.")

    # 5. Vulnerability category weighting
    category = (vulnerability_category or "unknown").lower()

    if category == "cors":
        score += 10
        reasons.append("CORS issues can be meaningful if sensitive authenticated data access is confirmed.")

    elif category == "security_header":
        score -= 5
        reasons.append("Missing security headers alone are often not reportable.")

    elif category == "subdomain_takeover":
        score += 35
        reasons.append("Subdomain takeover candidates can be high value if confirmed.")

    elif category == "exposed_file":
        score += 25
        reasons.append("Exposed files may be high value if sensitive content is confirmed.")

    elif category == "open_redirect":
        score += 15
        reasons.append("Open redirect candidates may matter if exploit impact is shown.")

    elif category == "recon_summary":
        score += 0
        reasons.append("Recon summary is useful for triage but not itself a vulnerability.")

    # 6. should_report flag
    if should_report:
        score += 30
        reasons.append("Validator marked this as potentially reportable.")

    # Clamp score
    if score < 0:
        score = 0

    if score >= 80:
        priority = "high"
    elif score >= 40:
        priority = "medium"
    else:
        priority = "low"

    return {
        "priority": priority,
        "score": score,
        "reasons": reasons
    }


def score_workflow_priority(
    endpoint_classification: dict,
    http_result: dict | None = None,
    security_result: dict | None = None,
    cors_result: dict | None = None
) -> dict:
    """
    Score the overall passive recon workflow priority.
    """

    http_result = http_result or {}
    security_result = security_result or {}
    cors_result = cors_result or {}

    score = 0
    reasons = []

    endpoint_type = endpoint_classification.get("classification", "unknown")

    # Endpoint importance
    if endpoint_type in ["admin_panel", "auth_service"]:
        score += 30
        reasons.append(f"High-value endpoint classification: {endpoint_type}.")

    elif endpoint_type == "api":
        score += 25
        reasons.append("API endpoint may be more relevant for auth/CORS/access-control review.")

    elif endpoint_type == "graphql":
        score += 25
        reasons.append("GraphQL endpoint may require focused manual review.")

    elif endpoint_type == "frontend":
        score += 10
        reasons.append("Frontend endpoint may be relevant for JS, headers, and client-side checks.")

    elif endpoint_type in ["static_asset", "cdn"]:
        score -= 10
        reasons.append("Static/CDN endpoint usually has lower impact.")

    # Security headers
    security_status = _validator_status(security_result)
    security_severity = _validator_severity(security_result)
    security_confidence = _validator_confidence(security_result)
    security_should_report = _validator_should_report(security_result)

    security_priority = score_finding_priority(
        finding_type="candidate_finding" if security_status == "candidate_finding" else "observation",
        vulnerability_category="security_header",
        endpoint_classification=endpoint_classification,
        severity=security_severity,
        confidence=security_confidence,
        status=security_status,
        should_report=security_should_report
    )

    score += int(security_priority.get("score", 0) * 0.35)

    if security_status == "candidate_finding":
        reasons.append("Security headers produced a candidate finding.")

    # CORS
    cors_status = _validator_status(cors_result)
    cors_severity = _validator_severity(cors_result)
    cors_confidence = _validator_confidence(cors_result)
    cors_should_report = _validator_should_report(cors_result)

    cors_priority = score_finding_priority(
        finding_type="candidate_finding" if cors_status == "candidate_finding" else "observation",
        vulnerability_category="cors",
        endpoint_classification=endpoint_classification,
        severity=cors_severity,
        confidence=cors_confidence,
        status=cors_status,
        should_report=cors_should_report
    )

    score += int(cors_priority.get("score", 0) * 0.45)

    if cors_status == "candidate_finding":
        reasons.append("CORS produced a candidate finding.")

    # HTTP probe hints
    http_summary = http_result.get("probe_summary", {})
    status_code = http_summary.get("status_code")

    if status_code in [401, 403]:
        score += 10
        reasons.append(f"HTTP status {status_code} may indicate protected or access-controlled endpoint.")

    elif status_code in [500, 502, 503]:
        score += 10
        reasons.append(f"HTTP status {status_code} may deserve reliability or error handling review.")

    elif status_code == 200:
        reasons.append("HTTP endpoint is reachable.")

    # Clamp score
    if score < 0:
        score = 0

    if score >= 80:
        priority = "high"
    elif score >= 40:
        priority = "medium"
    else:
        priority = "low"

    if not reasons:
        reasons.append("No strong priority signals detected.")

    return {
        "priority": priority,
        "score": score,
        "reasons": reasons,
        "components": {
            "security_headers_priority": security_priority,
            "cors_priority": cors_priority
        }
    }