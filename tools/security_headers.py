from tools.http_probe import http_probe


RECOMMENDED_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
]


def security_headers_check(target: str) -> dict:
    probe = http_probe(target)

    if probe.get("blocked"):
        return {
            "target": target,
            "blocked": True,
            "scope": probe.get("scope"),
            "reason": probe.get("reason")
        }

    if "error" in probe:
        return {
            "target": target,
            "error": probe["error"],
            "probe": probe
        }

    headers = {
        k.lower(): v
        for k, v in probe.get("headers", {}).items()
    }

    present = {}
    missing = []

    for header in RECOMMENDED_HEADERS:
        if header in headers:
            present[header] = headers[header]
        else:
            missing.append(header)

    severity = "info"

    if "x-frame-options" in missing and "content-security-policy" in missing:
        severity = "low"

    return {
        "target": target,
        "url": probe.get("final_url"),
        "status_code": probe.get("status_code"),
        "blocked": False,
        "present": present,
        "missing": missing,
        "severity": severity,
        "note": "Missing security headers are usually low or informational unless combined with concrete impact.",
        "probe": {
            "title": probe.get("title"),
            "content_type": probe.get("content_type"),
            "body_size": probe.get("body_size")
        }
    }