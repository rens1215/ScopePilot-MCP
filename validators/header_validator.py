def validate_security_headers(header_result: dict, endpoint_classification: dict | None = None) -> dict:
    """
    Validate security header check result and classify it as:
    - observation
    - candidate_finding
    - confirmed_finding

    This validator is intentionally conservative.
    Missing security headers alone are usually informational or low severity
    unless there is concrete impact.
    """

    endpoint_classification = endpoint_classification or {
        "classification": "unknown",
        "confidence": "low",
        "reason": "No endpoint classification provided."
    }

    classification = endpoint_classification.get("classification", "unknown")
    missing = header_result.get("missing", [])
    present = header_result.get("present", {})

    if not isinstance(missing, list):
        missing = []

    if not isinstance(present, dict):
        present = {}

    if header_result.get("blocked"):
        return {
            "status": "observation",
            "severity": "info",
            "confidence": "high",
            "should_report": False,
            "reason": "Target was blocked by scope guard.",
            "false_positive_notes": []
        }

    if header_result.get("error"):
        return {
            "status": "needs_manual_validation",
            "severity": "info",
            "confidence": "low",
            "should_report": False,
            "reason": "Security header check failed and requires manual validation.",
            "false_positive_notes": [
                "Network or target availability issues can cause incomplete results."
            ]
        }

    if not missing:
        return {
            "status": "observation",
            "severity": "info",
            "confidence": "high",
            "should_report": False,
            "reason": "No important security headers were missing.",
            "false_positive_notes": []
        }

    false_positive_notes = []

    if classification in ["static_asset", "cdn"]:
        false_positive_notes.append(
            "Missing headers on static assets or CDN-hosted resources are usually lower impact."
        )

        return {
            "status": "observation",
            "severity": "info",
            "confidence": "medium",
            "should_report": False,
            "reason": "Missing security headers were found, but the endpoint appears to be static/CDN content.",
            "false_positive_notes": false_positive_notes
        }

    missing_set = set(missing)

    missing_csp = "content-security-policy" in missing_set
    missing_xfo = "x-frame-options" in missing_set
    missing_hsts = "strict-transport-security" in missing_set
    missing_xcto = "x-content-type-options" in missing_set
    missing_referrer = "referrer-policy" in missing_set
    missing_permissions = "permissions-policy" in missing_set

    important_missing_count = sum([
        missing_csp,
        missing_xfo,
        missing_hsts,
        missing_xcto,
        missing_referrer,
        missing_permissions
    ])

    # Conservative rule:
    # Missing headers alone should not be considered a confirmed vulnerability.
    if missing_csp and missing_xfo and classification in ["frontend", "auth_service", "admin_panel"]:
        return {
            "status": "candidate_finding",
            "severity": "low",
            "confidence": "medium",
            "should_report": False,
            "reason": (
                "Content-Security-Policy and X-Frame-Options are missing on an interactive page. "
                "This may increase client-side attack surface, but concrete exploit impact is not confirmed."
            ),
            "false_positive_notes": [
                "Missing headers alone are often not reportable in bug bounty programs.",
                "Clickjacking impact requires confirming that sensitive actions can be framed.",
                "Missing CSP becomes more meaningful if XSS or dangerous inline script behavior exists."
            ]
        }

    if missing_hsts and classification in ["frontend", "auth_service", "admin_panel"]:
        return {
            "status": "observation",
            "severity": "low",
            "confidence": "medium",
            "should_report": False,
            "reason": (
                "Strict-Transport-Security is missing on a likely interactive HTTPS endpoint. "
                "This is usually a low-severity hardening issue unless concrete downgrade risk is shown."
            ),
            "false_positive_notes": [
                "Some programs treat missing HSTS as informational or out-of-scope.",
                "Impact depends on whether the domain is HTTPS-only and whether users can be downgraded."
            ]
        }

    if important_missing_count >= 3 and classification in ["frontend", "auth_service", "admin_panel"]:
        return {
            "status": "observation",
            "severity": "low",
            "confidence": "medium",
            "should_report": False,
            "reason": (
                "Multiple recommended security headers are missing on an interactive endpoint. "
                "This is a hardening observation unless a concrete exploit chain is demonstrated."
            ),
            "false_positive_notes": [
                "Many bug bounty programs do not accept missing security headers without practical impact."
            ]
        }

    return {
        "status": "observation",
        "severity": "info",
        "confidence": "medium",
        "should_report": False,
        "reason": "One or more recommended security headers are missing, but no concrete security impact was confirmed.",
        "false_positive_notes": [
            "Missing security headers alone are usually informational.",
            "Manual validation is required before considering a bug bounty report."
        ]
    }