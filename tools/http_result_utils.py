SAFE_HEADER_KEYS = {
    "content-type",
    "content-length",
    "last-modified",
    "etag",
    "cache-control",
    "location",
}

SENSITIVE_HEADER_MARKERS = {
    "cookie",
    "authorization",
    "token",
    "secret",
    "api-key",
    "apikey",
}


def _request_error(url: str, message: str) -> dict:
    return {
        "url": url,
        "blocked": False,
        "status": "request_error",
        "error": message,
    }


def safe_http_probe_call(url: str, probe_func=None) -> tuple[dict, bool]:
    """
    Safely call an HTTP probe helper and normalize failures.

    This utility does not import or call http_probe at module import time. If
    probe_func is None, it lazily resolves tools.http_probe.http_probe only when
    this function is called. It does not add new request behavior by itself and
    should be used only by workflows that already own scope checks, request
    budgets, and approval policy.

    Safety boundaries:
    - Does not exploit, fuzz, brute force, submit forms, use credentials, or
      perform state-changing actions.
    - Does not save cookies, tokens, secrets, personal data, payment data, or
      full response bodies.
    - Converts unavailable helpers, exceptions, and malformed returns into
      request_error-style dictionaries instead of crashing callers.
    """
    helper = probe_func
    if helper is None:
        try:
            from tools.http_probe import http_probe as helper
        except Exception as error:
            return _request_error(url, f"HTTP probe helper is unavailable: {error}"), False

    try:
        probe = helper(url)
    except Exception as error:
        return _request_error(url, f"HTTP probe raised exception: {error}"), True

    if not isinstance(probe, dict):
        return _request_error(url, "HTTP probe returned a non-dict result."), True

    return probe, True


def get_content_type(probe: dict) -> str:
    """
    Extract a normalized Content-Type value from safe probe metadata.

    This helper performs local dict parsing only. It sends no requests, executes
    no tools, calls no workflows, and stores no response body. Charset and other
    parameters are stripped so callers can compare media types consistently.
    """
    if not isinstance(probe, dict):
        return ""

    value = probe.get("content_type", "")
    if not value and isinstance(probe.get("headers"), dict):
        for key, header_value in probe["headers"].items():
            if str(key).lower() == "content-type":
                value = header_value
                break

    return str(value).split(";", 1)[0].strip().lower()


def _is_sensitive_header(header_name: str) -> bool:
    lowered = header_name.lower()
    return any(marker in lowered for marker in SENSITIVE_HEADER_MARKERS)


def headers_summary(headers: dict | None) -> dict:
    """
    Return a safe, non-sensitive summary of response headers.

    This helper keeps only allowlisted metadata headers and excludes cookies,
    authorization material, API keys, token-like headers, and secret-like
    headers. It does not send requests, execute tools, call workflows, exploit,
    fuzz, brute force, submit forms, use credentials, or store sensitive data.
    """
    if not isinstance(headers, dict):
        return {}

    summary = {}
    for key, value in headers.items():
        lowered = str(key).lower()
        if lowered not in SAFE_HEADER_KEYS:
            continue
        if _is_sensitive_header(lowered):
            continue
        summary[lowered] = value

    return summary


def probe_body_text(probe: dict) -> str:
    """
    Extract response text from common probe body fields.

    This helper only reads local probe dictionaries. It does not send requests,
    execute JavaScript, call workflows, exploit, fuzz, brute force, or store the
    returned body. Callers must still avoid persisting full sensitive response
    bodies.
    """
    if not isinstance(probe, dict):
        return ""

    for key in ("body", "text", "body_text", "content", "response_text"):
        value = probe.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")

    return ""


def base_http_observation(
    url: str,
    probe: dict,
    status: str,
    depth: int | None = None,
    error: str | None = None,
) -> dict:
    """
    Build a safe HTTP observation from probe metadata.

    The observation intentionally excludes full response bodies and sensitive
    headers. This is result-shaping only: it does not send HTTP requests, call
    workflows, execute tools, exploit, fuzz, brute force, submit forms, use
    credentials, or perform state-changing actions.
    """
    safe_probe = probe if isinstance(probe, dict) else {}

    return {
        "url": url,
        "depth": depth,
        "status": status,
        "status_code": safe_probe.get("status_code"),
        "content_type": get_content_type(safe_probe),
        "body_size": safe_probe.get("body_size"),
        "headers_summary": headers_summary(safe_probe.get("headers")),
        "error": error if error is not None else safe_probe.get("error"),
    }


def is_allowed_content_type(content_type: str, allowed_types: set[str]) -> bool:
    """
    Check whether a Content-Type is in an allowed media-type set.

    This helper performs local string comparison only. It does not send
    requests, execute tools, call workflows, exploit, fuzz, brute force, submit
    forms, use credentials, or modify target state.
    """
    if not isinstance(allowed_types, set):
        return False

    normalized = str(content_type or "").split(";", 1)[0].strip().lower()
    allowed = {str(item).strip().lower() for item in allowed_types}
    return normalized in allowed
