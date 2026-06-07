def _safe_requests_sent(value) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0

    return max(parsed, 0)


def _safe_scan_level(value) -> str:
    if value is None:
        return "safe"

    normalized = str(value).strip()
    if not normalized:
        return "safe"

    return normalized


def _safe_bool(value) -> bool:
    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y"}:
            return True
        if lowered in {"false", "0", "no", "n", ""}:
            return False

    return bool(value)


def build_safety_metadata(
    requests_sent=0,
    scan_level="safe",
    fuzzing=False,
    bruteforce=False,
    exploitation=False,
    crawling=False,
    credentialed_request=False,
    state_changing=False,
) -> dict:
    """
    Build standardized safety metadata for workflow-style results.

    This helper only creates a local dictionary. It does not execute tools,
    call workflows, call http_probe, send HTTP or other external requests,
    modify state, submit forms, use credentials, or perform validation. Defaults
    are intentionally safe so new callers start from a no-request, no-risk
    baseline and must opt in to risk flags explicitly.
    """
    # Fail closed on malformed request counts: a negative or non-numeric value
    # must never make safety metadata imply that negative requests occurred.
    safe_requests_sent = _safe_requests_sent(requests_sent)

    return {
        "requests_sent": safe_requests_sent,
        "scan_level": _safe_scan_level(scan_level),
        "fuzzing": _safe_bool(fuzzing),
        "bruteforce": _safe_bool(bruteforce),
        "exploitation": _safe_bool(exploitation),
        "crawling": _safe_bool(crawling),
        "credentialed_request": _safe_bool(credentialed_request),
        "state_changing": _safe_bool(state_changing),
    }
