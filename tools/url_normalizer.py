from urllib.parse import urljoin, urlsplit, urlunsplit


SUPPORTED_SCHEMES = {"http", "https"}


def _result(
    input_url: str,
    ok: bool,
    normalized_url: str = "",
    scheme: str = "",
    hostname: str = "",
    path: str = "",
    query: str = "",
    error: str = "",
) -> dict:
    return {
        "ok": ok,
        "input_url": input_url,
        "normalized_url": normalized_url,
        "scheme": scheme,
        "hostname": hostname,
        "path": path,
        "query": query,
        "error": error,
    }


def normalize_url(url: str, base_url: str | None = None) -> dict:
    """
    Normalize an absolute URL or a relative URL with a base URL.

    This helper does not send HTTP requests, call workflows, execute tools, or
    touch target state. It only parses URL strings locally, removes fragments,
    normalizes scheme/hostname casing, preserves path/query, and rejects
    unsupported schemes such as javascript:, data:, file:, and ftp:.

    The function returns a loaded-style dictionary instead of raising to callers
    so inventory builders can fail safely while processing untrusted URL text.
    """
    if not isinstance(url, str) or not url.strip():
        return _result(str(url), False, error="URL must be a non-empty string.")

    input_url = url
    candidate = url.strip()

    try:
        if base_url is not None:
            base_parts = urlsplit(base_url)
            base_scheme = base_parts.scheme.lower()
            if base_scheme not in SUPPORTED_SCHEMES or not base_parts.hostname:
                return _result(input_url, False, error="Base URL must be absolute HTTP or HTTPS.")
            candidate = urljoin(base_url, candidate)

        parts = urlsplit(candidate)
    except ValueError as error:
        return _result(input_url, False, error=f"Invalid URL: {error}")

    scheme = parts.scheme.lower()
    if scheme not in SUPPORTED_SCHEMES:
        return _result(input_url, False, error=f"Unsupported URL scheme: {parts.scheme or 'missing'}.")

    if not parts.hostname:
        return _result(input_url, False, error="URL must include a hostname.")

    # Avoid carrying credentials into inventory metadata.
    if parts.username or parts.password:
        return _result(input_url, False, error="URL credentials are not allowed in inventory.")

    hostname = parts.hostname.lower()

    try:
        port = parts.port
    except ValueError as error:
        return _result(input_url, False, error=f"Invalid URL port: {error}")

    if ":" in hostname and not hostname.startswith("["):
        netloc = f"[{hostname}]"
    else:
        netloc = hostname

    if port is not None:
        netloc = f"{netloc}:{port}"

    # Fragment is intentionally discarded; path and query are preserved.
    normalized_url = urlunsplit((scheme, netloc, parts.path, parts.query, ""))

    return _result(
        input_url=input_url,
        ok=True,
        normalized_url=normalized_url,
        scheme=scheme,
        hostname=hostname,
        path=parts.path,
        query=parts.query,
    )
