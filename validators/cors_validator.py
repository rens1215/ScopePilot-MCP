def _normalize_header_dict(headers: dict | None) -> dict:
    """
    Normalize response headers to lowercase keys.
    """
    if not isinstance(headers, dict):
        return {}

    return {
        str(k).lower(): v
        for k, v in headers.items()
    }


def _to_bool_header(value) -> bool:
    """
    Convert common header values to bool.
    """
    if value is None:
        return False

    return str(value).strip().lower() == "true"


def validate_cors(cors_result: dict, endpoint_classification: dict | None = None) -> dict:
    """
    Validate CORS observation result conservatively.

    This validator does not confirm exploitability.
    It only classifies the CORS behavior as:
    - observation
    - candidate_finding
    - needs_manual_validation

    CORS findings require manual validation before reporting.
    """

    endpoint_classification = endpoint_classification or {
        "classification": "unknown",
        "confidence": "low",
        "reason": "No endpoint classification provided."
    }

    classification = endpoint_classification.get("classification", "unknown")

    if cors_result.get("blocked"):
        return {
            "status": "observation",
            "severity": "info",
            "confidence": "high",
            "should_report": False,
            "reason": "Target was blocked by scope guard.",
            "false_positive_notes": []
        }

    if cors_result.get("error"):
        return {
            "status": "needs_manual_validation",
            "severity": "info",
            "confidence": "low",
            "should_report": False,
            "reason": "CORS observation failed and requires manual validation.",
            "false_positive_notes": [
                "Network or target availability issues can cause incomplete results."
            ]
        }

    headers = _normalize_header_dict(cors_result.get("headers", {}))

    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials")
    acam = headers.get("access-control-allow-methods")
    acah = headers.get("access-control-allow-headers")
    vary = headers.get("vary")

    origin_tested = cors_result.get("origin_tested")
    origin_reflected = cors_result.get("origin_reflected", False)
    credentials_allowed = _to_bool_header(acac)

    cors_headers_present = any([
        acao,
        acac,
        acam,
        acah
    ])

    if not cors_headers_present:
        return {
            "status": "observation",
            "severity": "info",
            "confidence": "high",
            "should_report": False,
            "reason": "No CORS response headers were detected.",
            "false_positive_notes": []
        }

    false_positive_notes = []

    # Wildcard CORS without credentials is usually not a reportable vulnerability.
    if acao == "*" and not credentials_allowed:
        return {
            "status": "observation",
            "severity": "info",
            "confidence": "high",
            "should_report": False,
            "reason": "Wildcard ACAO was detected without credentials. This is usually not a security vulnerability by itself.",
            "false_positive_notes": [
                "Access-Control-Allow-Origin: * without credentials is commonly used for public resources.",
                "This is usually not reportable unless sensitive unauthenticated data exposure is demonstrated."
            ]
        }

    # ACAO '*' with ACAC true is invalid in modern browsers for credentialed requests.
    if acao == "*" and credentials_allowed:
        return {
            "status": "observation",
            "severity": "info",
            "confidence": "medium",
            "should_report": False,
            "reason": "ACAO is wildcard and ACAC is true, but browsers do not allow credentialed reads with wildcard ACAO.",
            "false_positive_notes": [
                "This combination often appears suspicious but is usually not exploitable in browsers.",
                "Manual browser-based validation is required before considering it a finding."
            ]
        }

    # Origin reflection + credentials is potentially interesting, but not confirmed.
    if origin_reflected and credentials_allowed:
        severity = "medium" if classification in ["api", "auth_service", "admin_panel"] else "low"

        return {
            "status": "candidate_finding",
            "severity": severity,
            "confidence": "medium",
            "should_report": False,
            "reason": (
                "The tested Origin appears to be reflected and credentials are allowed. "
                "This may indicate a CORS misconfiguration, but sensitive authenticated data access was not confirmed."
            ),
            "false_positive_notes": [
                "Origin reflection alone is not enough to confirm a vulnerability.",
                "A valid authenticated test account and a non-destructive endpoint are required for manual validation.",
                "Do not report unless sensitive data can be read cross-origin within policy."
            ]
        }

    # Origin reflection without credentials is usually low impact.
    if origin_reflected and not credentials_allowed:
        return {
            "status": "observation",
            "severity": "info",
            "confidence": "medium",
            "should_report": False,
            "reason": "The tested Origin appears to be reflected, but credentials are not allowed.",
            "false_positive_notes": [
                "Without credentials, impact is usually limited to public unauthenticated responses.",
                "Manual validation is required to determine whether sensitive public data is exposed."
            ]
        }

    # Specific ACAO value with credentials may be legitimate.
    if acao and acao != "*" and credentials_allowed:
        return {
            "status": "observation",
            "severity": "info",
            "confidence": "medium",
            "should_report": False,
            "reason": "A specific ACAO value with credentials was detected. This may be legitimate if the origin is trusted.",
            "false_positive_notes": [
                "CORS with credentials is not automatically vulnerable.",
                "Need to verify whether the allowed origin is trusted and controlled by the program."
            ]
        }

    return {
        "status": "observation",
        "severity": "info",
        "confidence": "medium",
        "should_report": False,
        "reason": "CORS headers were detected, but no clearly risky behavior was confirmed.",
        "false_positive_notes": [
            "CORS observations usually require manual validation before reporting.",
            "Do not classify as confirmed without proof of cross-origin sensitive data access."
        ]
    }