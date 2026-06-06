from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

from tools.endpoint_inventory import build_inventory_item
from tools.js_endpoint_extractor import extract_js_endpoints
from tools.logger import log_event
from tools.scope_guard import check_scope
from tools.url_normalizer import normalize_url
from validators.inventory_validator import validate_inventory_item

try:
    from tools.http_probe import http_probe
except ImportError:
    http_probe = None


DEFAULT_MAX_JS_FILES = 20
HARD_MAX_JS_FILES = 30
HARD_MAX_TOTAL_REQUESTS = 31
DEFAULT_MAX_JS_BYTES = 500000
DEFAULT_MAX_CANDIDATES = 100

ALLOWED_HTML_CONTENT_TYPES = {
    "text/html",
    "application/xhtml+xml",
}

ALLOWED_JS_CONTENT_TYPES = {
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "text/ecmascript",
}

SAFE_HEADER_KEYS = {
    "content-type",
    "content-length",
    "last-modified",
    "etag",
    "cache-control",
}


class _ScriptSrcParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.script_srcs = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return

        for name, value in attrs:
            if name.lower() == "src" and value:
                self.script_srcs.append(value.strip())


def _safety(requests_sent: int, scan_level: str = "medium-risk") -> dict:
    return {
        "requests_sent": requests_sent,
        "scan_level": scan_level,
        "fuzzing": False,
        "bruteforce": False,
        "exploitation": False,
        "crawling": False,
        "credentialed_request": False,
    }


def _nonnegative_int(value: int, default: int = 0) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default

    return max(parsed, 0)


def _effective_max_js_files(max_js_files: int) -> int:
    requested = _nonnegative_int(max_js_files)
    return min(requested, HARD_MAX_JS_FILES, HARD_MAX_TOTAL_REQUESTS - 1)


def _target_url(target: str) -> str:
    candidate = target if "://" in target else f"https://{target}"
    parts = urlsplit(candidate)
    scheme = (parts.scheme or "https").lower()
    netloc = parts.netloc or parts.path
    path = parts.path if parts.netloc else ""
    return urlunsplit((scheme, netloc, path or "/", parts.query, ""))


def _headers_summary(headers: dict | None) -> dict:
    if not isinstance(headers, dict):
        return {}

    # Store only safe metadata headers. Never copy Set-Cookie, Authorization,
    # tokens, secrets, personal data, or raw response bodies into inventory.
    summary = {}
    for key, value in headers.items():
        lowered = str(key).lower()
        if lowered in SAFE_HEADER_KEYS:
            summary[lowered] = value
    return summary


def _content_type(probe: dict) -> str:
    value = probe.get("content_type", "")
    if not value and isinstance(probe.get("headers"), dict):
        value = probe["headers"].get("content-type", "")

    return str(value).split(";", 1)[0].strip().lower()


def _content_type_allowed(probe: dict, allowed_types: set[str]) -> tuple[bool, str]:
    content_type = _content_type(probe)
    if not content_type:
        return True, "Content-Type is empty; conservatively allowed for static parsing."

    if content_type in allowed_types:
        return True, ""

    return False, f"Unsupported content type for static parsing: {content_type}."


def _safe_http_probe(url: str) -> tuple[dict, bool]:
    """
    Call the low-risk HTTP helper and normalize failures into a probe dict.

    The workflow uses this helper for one frontend page and a bounded number of
    same-scope JavaScript files. Exceptions or malformed helper output become
    request_error observations instead of crashing the workflow.
    """
    if http_probe is None:
        return {
            "blocked": False,
            "error": "HTTP probe helper is unavailable.",
        }, False

    try:
        probe = http_probe(url)
    except Exception as error:
        return {
            "blocked": False,
            "error": f"HTTP probe raised exception: {error}",
        }, True

    if not isinstance(probe, dict):
        return {
            "blocked": False,
            "error": "HTTP probe returned a non-dict result.",
        }, True

    return probe, True


def _probe_body_text(probe: dict) -> str:
    for key in ("body", "text", "body_text", "content", "response_text"):
        value = probe.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
    return ""


def _extract_script_srcs(html_text: str) -> list[str]:
    parser = _ScriptSrcParser()
    parser.feed(html_text)
    return parser.script_srcs


def _same_host_or_in_scope(normalized_url: str, target_hostname: str) -> bool:
    candidate_hostname = (urlsplit(normalized_url).hostname or "").lower()
    if candidate_hostname == target_hostname:
        return True

    # This secondary scope check is policy evaluation only. It does not send
    # requests and prevents cross-scope JS files or endpoint candidates from
    # being processed.
    try:
        scope = check_scope(normalized_url)
    except Exception:
        return False

    return bool(scope.get("in_scope"))


def _build_candidate(target: str, raw_candidate: str, normalized_url: str, js_url: str, probe: dict) -> dict:
    item = build_inventory_item(
        target=target,
        url=raw_candidate,
        normalized_url=normalized_url,
        source="javascript_static_analysis",
        discovered_by="safe_js_endpoint_extraction_workflow",
        evidence={
            "status_code": probe.get("status_code"),
            "content_type": probe.get("content_type", ""),
            "body_size": probe.get("body_size"),
            "headers_summary": _headers_summary(probe.get("headers")),
        },
        notes=(
            f"Endpoint candidate extracted from JavaScript file {js_url}. "
            "The workflow did not execute JavaScript and did not request this candidate URL."
        ),
    )

    validation = validate_inventory_item(item)
    item["endpoint_type"] = validation.get("endpoint_type", "unknown")
    item["priority"] = validation.get("priority", "low")
    item["confidence"] = validation.get("confidence", "low")
    item["recommended_next_skill"] = validation.get("recommended_next_skill", "")
    item["validator_result"] = validation

    return item


def _base_observation(url: str, source: str, probe: dict, status: str, error: str | None = None) -> dict:
    return {
        "source": source,
        "url": url,
        "status": status,
        "status_code": probe.get("status_code"),
        "content_type": probe.get("content_type", ""),
        "body_size": probe.get("body_size"),
        "headers_summary": _headers_summary(probe.get("headers")),
        "error": error if error is not None else probe.get("error"),
    }


def safe_js_endpoint_extraction_workflow(
    target: str,
    max_js_files: int = DEFAULT_MAX_JS_FILES,
    max_js_bytes: int = DEFAULT_MAX_JS_BYTES,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> dict:
    """
    Extract endpoint candidates from bounded same-scope JavaScript files.

    This is a medium-risk static analysis workflow. It checks scope first, fetches
    the target frontend page once, extracts script src references from HTML, and
    fetches at most 30 same-host or in-scope JavaScript files. The total hard
    request cap is 31: one HTML request plus up to 30 JavaScript requests.

    Safety boundaries:
    - This is not a crawler and safety.crawling is always false.
    - Does not execute JavaScript or evaluate JavaScript.
    - Does not request endpoints extracted from JavaScript.
    - Does not fuzz, brute force, exploit, submit forms, use credentials, run
      DoS, or perform state-changing actions.
    - Does not save cookies, tokens, secrets, personal data, payment data, or
      complete response bodies.
    """
    requested_max_js_files = max_js_files
    effective_max_js_files = _effective_max_js_files(max_js_files)
    effective_max_js_bytes = _nonnegative_int(max_js_bytes)
    effective_max_candidates = _nonnegative_int(max_candidates)

    limit_summary = {
        "requested_max_js_files": requested_max_js_files,
        "effective_max_js_files": effective_max_js_files,
        "hard_max_js_files": HARD_MAX_JS_FILES,
        "hard_max_total_requests": HARD_MAX_TOTAL_REQUESTS,
        "max_js_bytes": effective_max_js_bytes,
        "max_candidates": effective_max_candidates,
    }

    log_event(f"workflow: safe_js_endpoint_extraction start target={target}")
    scope = check_scope(target)

    log_event(
        f"workflow: safe_js_endpoint_extraction scope target={target} "
        f"in_scope={scope.get('in_scope')} hostname={scope.get('hostname')}"
    )

    if not scope.get("in_scope"):
        return {
            "target": target,
            "stopped": True,
            "reason": "Target is not in scope.",
            "scope": scope,
            "target_url": None,
            "observations": [],
            "script_urls": [],
            "skipped_scripts": [],
            "endpoint_candidates": [],
            "skipped_endpoint_candidates": [],
            "inventory_candidates": [],
            "summary": {
                **limit_summary,
                "html_requested": False,
                "script_count": 0,
                "endpoint_candidate_count": 0,
                "inventory_candidate_count": 0,
                "skipped_script_count": 0,
                "skipped_endpoint_candidate_count": 0,
            },
            "safety": _safety(0, scan_level="blocked"),
        }

    target_url = _target_url(target)
    target_hostname = (scope.get("hostname") or "").lower()
    requests_sent = 0
    observations = []
    script_urls = []
    skipped_scripts = []
    endpoint_candidates = []
    skipped_endpoint_candidates = []
    inventory_candidates = []
    seen_inventory_urls = set()

    log_event(f"workflow: safe_js_endpoint_extraction html_request_start url={target_url}")
    html_probe, helper_called = _safe_http_probe(target_url)
    if helper_called and not html_probe.get("blocked"):
        requests_sent += 1

    log_event(
        f"workflow: safe_js_endpoint_extraction html_request_done url={target_url} "
        f"blocked={html_probe.get('blocked')} status={html_probe.get('status_code')} "
        f"error={html_probe.get('error')}"
    )

    if html_probe.get("error"):
        observations.append(_base_observation(target_url, "html", html_probe, "request_error"))
    elif html_probe.get("blocked"):
        observations.append(_base_observation(target_url, "html", html_probe, "blocked"))
    else:
        html_allowed, html_content_type_reason = _content_type_allowed(html_probe, ALLOWED_HTML_CONTENT_TYPES)
        if not html_allowed:
            observations.append(
                _base_observation(
                    target_url,
                    "html",
                    html_probe,
                    "unsupported_content_type",
                    error=html_content_type_reason,
                )
            )
        else:
            html_text = _probe_body_text(html_probe)
            if not html_text:
                observations.append(
                    _base_observation(
                        target_url,
                        "html",
                        html_probe,
                        "parse_error",
                        error="HTML response body was not available.",
                    )
                )
            else:
                discovered_script_srcs = _extract_script_srcs(html_text)
                html_observation = {
                    **_base_observation(target_url, "html", html_probe, "parsed"),
                    "script_src_count": len(discovered_script_srcs),
                }
                if html_content_type_reason:
                    html_observation["content_type_note"] = html_content_type_reason
                observations.append(html_observation)

                for script_src in discovered_script_srcs:
                    normalized = normalize_url(script_src, base_url=target_url)
                    if not normalized.get("ok"):
                        skipped_scripts.append(
                            {
                                "src": script_src,
                                "reason": normalized.get("error", "Script URL normalization failed."),
                            }
                        )
                        continue

                    js_url = normalized.get("normalized_url", "")
                    if not _same_host_or_in_scope(js_url, target_hostname):
                        skipped_scripts.append(
                            {
                                "src": script_src,
                                "normalized_url": js_url,
                                "reason": "Script URL is outside target host and configured scope.",
                            }
                        )
                        continue

                    if len(script_urls) >= effective_max_js_files:
                        skipped_scripts.append(
                            {
                                "src": script_src,
                                "normalized_url": js_url,
                                "reason": "effective_max_js_files limit reached.",
                            }
                        )
                        continue

                    # The hard total request cap is enforced even if a caller
                    # provides a larger max_js_files value.
                    if requests_sent >= HARD_MAX_TOTAL_REQUESTS:
                        skipped_scripts.append(
                            {
                                "src": script_src,
                                "normalized_url": js_url,
                                "reason": "hard max total request limit reached.",
                            }
                        )
                        continue

                    script_urls.append(js_url)

                    log_event(f"workflow: safe_js_endpoint_extraction js_request_start url={js_url}")
                    js_probe, js_helper_called = _safe_http_probe(js_url)
                    if js_helper_called and not js_probe.get("blocked"):
                        requests_sent += 1

                    log_event(
                        f"workflow: safe_js_endpoint_extraction js_request_done url={js_url} "
                        f"blocked={js_probe.get('blocked')} status={js_probe.get('status_code')} "
                        f"error={js_probe.get('error')}"
                    )

                    if js_probe.get("error"):
                        observations.append(_base_observation(js_url, "javascript", js_probe, "request_error"))
                        continue

                    if js_probe.get("blocked"):
                        observations.append(_base_observation(js_url, "javascript", js_probe, "blocked"))
                        continue

                    js_allowed, js_content_type_reason = _content_type_allowed(js_probe, ALLOWED_JS_CONTENT_TYPES)
                    if not js_allowed:
                        observations.append(
                            _base_observation(
                                js_url,
                                "javascript",
                                js_probe,
                                "unsupported_content_type",
                                error=js_content_type_reason,
                            )
                        )
                        continue

                    body_size = js_probe.get("body_size")
                    if isinstance(body_size, int) and body_size > effective_max_js_bytes:
                        observations.append(
                            _base_observation(
                                js_url,
                                "javascript",
                                js_probe,
                                "skipped_oversized",
                                error="JavaScript body_size exceeds max_js_bytes.",
                            )
                        )
                        continue

                    js_text = _probe_body_text(js_probe)
                    js_size = len(js_text.encode("utf-8"))
                    if not js_text:
                        observations.append(
                            _base_observation(
                                js_url,
                                "javascript",
                                js_probe,
                                "parse_error",
                                error="JavaScript response body was not available.",
                            )
                        )
                        continue

                    if js_size > effective_max_js_bytes:
                        observations.append(
                            _base_observation(
                                js_url,
                                "javascript",
                                js_probe,
                                "skipped_oversized",
                                error="JavaScript text exceeds max_js_bytes.",
                            )
                        )
                        continue

                    if effective_max_candidates <= 0:
                        observations.append(
                            {
                                **_base_observation(js_url, "javascript", js_probe, "parsed"),
                                "extracted_candidate_count": 0,
                                "reason": "max_candidates is 0; endpoint extraction skipped safely.",
                            }
                        )
                        continue

                    extraction = extract_js_endpoints(
                        js_text,
                        base_url=js_url,
                        max_candidates=effective_max_candidates,
                    )
                    if not extraction.get("ok"):
                        observations.append(
                            _base_observation(
                                js_url,
                                "javascript",
                                js_probe,
                                "parse_error",
                                error=extraction.get("error", "JavaScript endpoint extraction failed."),
                            )
                        )
                        continue

                    accepted_for_js = 0
                    for candidate in extraction.get("candidates", []):
                        normalized_candidate = normalize_url(candidate, base_url=js_url)
                        if not normalized_candidate.get("ok"):
                            skipped_endpoint_candidates.append(
                                {
                                    "candidate": candidate,
                                    "source_js": js_url,
                                    "reason": normalized_candidate.get("error", "Endpoint normalization failed."),
                                }
                            )
                            continue

                        normalized_url = normalized_candidate.get("normalized_url", "")
                        if not _same_host_or_in_scope(normalized_url, target_hostname):
                            skipped_endpoint_candidates.append(
                                {
                                    "candidate": candidate,
                                    "normalized_url": normalized_url,
                                    "source_js": js_url,
                                    "reason": "Endpoint candidate is outside target host and configured scope.",
                                }
                            )
                            continue

                        if normalized_url in seen_inventory_urls:
                            continue

                        seen_inventory_urls.add(normalized_url)
                        endpoint_candidates.append(normalized_url)
                        inventory_candidates.append(
                            _build_candidate(target, candidate, normalized_url, js_url, js_probe)
                        )
                        accepted_for_js += 1

                    js_observation = {
                        **_base_observation(js_url, "javascript", js_probe, "parsed"),
                        "extracted_candidate_count": accepted_for_js,
                    }
                    if js_content_type_reason:
                        js_observation["content_type_note"] = js_content_type_reason
                    observations.append(js_observation)
    log_event(
        f"workflow: safe_js_endpoint_extraction complete target={target} "
        f"requests_sent={requests_sent} scripts={len(script_urls)} "
        f"candidates={len(inventory_candidates)}"
    )

    return {
        "target": target,
        "stopped": False,
        "scope": scope,
        "target_url": target_url,
        "observations": observations,
        "script_urls": script_urls,
        "skipped_scripts": skipped_scripts,
        "endpoint_candidates": endpoint_candidates,
        "skipped_endpoint_candidates": skipped_endpoint_candidates,
        "inventory_candidates": inventory_candidates,
        "summary": {
            **limit_summary,
            "html_requested": True,
            "script_count": len(script_urls),
            "endpoint_candidate_count": len(endpoint_candidates),
            "inventory_candidate_count": len(inventory_candidates),
            "skipped_script_count": len(skipped_scripts),
            "skipped_endpoint_candidate_count": len(skipped_endpoint_candidates),
        },
        "safety": _safety(requests_sent),
    }
