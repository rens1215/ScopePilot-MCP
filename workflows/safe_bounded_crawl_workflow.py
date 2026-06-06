import time
from urllib.parse import urlsplit, urlunsplit

from tools.crawl_queue import CrawlQueue
from tools.endpoint_inventory import build_inventory_item
from tools.html_link_extractor import extract_html_links
from tools.logger import log_event
from tools.scope_guard import check_scope
from tools.url_normalizer import normalize_url
from validators.inventory_validator import validate_inventory_item

try:
    from tools.http_probe import http_probe
except ImportError:
    http_probe = None


ALLOWED_HTML_CONTENT_TYPES = {
    "text/html",
    "application/xhtml+xml",
}

HARD_MAX_REQUESTS = 30

SAFE_HEADER_KEYS = {
    "content-type",
    "content-length",
    "last-modified",
    "etag",
    "cache-control",
}


def _nonnegative_int(value: int, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default

    return max(parsed, 0)


def _nonnegative_float(value: float, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default

    return max(parsed, 0.0)


def _target_url(target: str) -> str:
    candidate = target if "://" in target else f"https://{target}"
    parts = urlsplit(candidate)
    scheme = (parts.scheme or "https").lower()
    netloc = parts.netloc or parts.path
    path = parts.path if parts.netloc else ""
    return urlunsplit((scheme, netloc, path or "/", parts.query, ""))


def _hostname(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _safety(requests_sent: int, scan_level: str = "medium-risk") -> dict:
    return {
        "requests_sent": requests_sent,
        "scan_level": scan_level,
        "fuzzing": False,
        "bruteforce": False,
        "exploitation": False,
        "crawling": True,
        "credentialed_request": False,
    }


def _headers_summary(headers: dict | None) -> dict:
    if not isinstance(headers, dict):
        return {}

    # Keep only non-sensitive metadata. Never copy Set-Cookie, Authorization,
    # tokens, secrets, personal data, payment data, or response bodies.
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


def _safe_http_probe(url: str) -> tuple[dict, bool]:
    """
    Call the low-risk HTTP helper and normalize failures into a probe dict.

    The bounded crawler uses the existing GET-only http_probe helper. It never
    submits forms, never sends credentials, and never uses state-changing HTTP
    methods. Helper exceptions or malformed return values become request_error
    observations instead of crashing the workflow.
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


def _base_observation(url: str, probe: dict, status: str, depth: int, error: str | None = None) -> dict:
    return {
        "url": url,
        "depth": depth,
        "status": status,
        "status_code": probe.get("status_code"),
        "content_type": _content_type(probe),
        "body_size": probe.get("body_size"),
        "headers_summary": _headers_summary(probe.get("headers")),
        "error": error if error is not None else probe.get("error"),
    }


def _same_host_or_in_scope(normalized_url: str, target_hostname: str) -> bool:
    candidate_hostname = _hostname(normalized_url)
    if candidate_hostname == target_hostname:
        return True

    # This is scope policy evaluation only. It does not send requests and is
    # used to allow configured in-scope hosts while rejecting out-of-scope links.
    try:
        scope = check_scope(normalized_url)
    except Exception:
        return False

    return bool(scope.get("in_scope"))


def _build_candidate(
    target: str,
    raw_url: str,
    normalized_url: str,
    source: str,
    discovered_from: str,
    probe: dict,
) -> dict:
    item = build_inventory_item(
        target=target,
        url=raw_url,
        normalized_url=normalized_url,
        source=source,
        discovered_by="safe_bounded_crawl_workflow",
        evidence={
            "status_code": probe.get("status_code"),
            "content_type": _content_type(probe),
            "body_size": probe.get("body_size"),
            "headers_summary": _headers_summary(probe.get("headers")),
        },
        notes=(
            f"Candidate discovered from HTML page {discovered_from}. "
            "This workflow builds attack surface inventory only. It does not "
            "download JavaScript, request API endpoints extracted from JS, "
            "submit forms, fuzz, brute force, exploit, or use credentials."
        ),
    )

    validation = validate_inventory_item(item)
    item["endpoint_type"] = validation.get("endpoint_type", "unknown")
    item["priority"] = validation.get("priority", "low")
    item["confidence"] = validation.get("confidence", "low")
    item["recommended_next_skill"] = validation.get("recommended_next_skill", "")
    item["validator_result"] = validation

    return item


def _append_candidate(
    candidates: list[dict],
    seen_inventory_urls: set[str],
    target: str,
    raw_url: str,
    normalized_url: str,
    source: str,
    discovered_from: str,
    probe: dict,
) -> None:
    if normalized_url in seen_inventory_urls:
        return

    seen_inventory_urls.add(normalized_url)
    candidates.append(
        _build_candidate(
            target=target,
            raw_url=raw_url,
            normalized_url=normalized_url,
            source=source,
            discovered_from=discovered_from,
            probe=probe,
        )
    )


def safe_bounded_crawl_workflow(
    target: str,
    max_pages: int = 30,
    max_depth: int = 2,
    max_requests: int = 30,
    rate_delay_seconds: float = 0.5,
    max_links_per_page: int = 200,
) -> dict:
    """
    Build endpoint inventory with bounded in-scope HTML crawling.

    This is a medium-risk bounded crawler for attack surface inventory only. It
    checks scope before any request and then uses only the GET-based http_probe
    helper for same-host or configured in-scope HTML pages.

    Safety boundaries:
    - Not an exploit workflow and not vulnerability validation.
    - Not unrestricted crawling; max_pages, max_depth, max_requests, and
      rate_delay_seconds are enforced. The workflow also keeps a hard request
      cap of 30 to match its medium-risk profile.
    - Does not POST, PUT, PATCH, DELETE, submit forms, fuzz, brute force,
      exploit, stress test, use credentials, or perform state-changing actions.
    - Does not save cookies, tokens, secrets, personal data, payment data, or
      full response bodies.
    - Does not download JavaScript; script src values become inventory
      candidates only. JS endpoint extraction belongs to
      safe_js_endpoint_extraction_workflow.
    """
    effective_max_pages = _nonnegative_int(max_pages, 30)
    effective_max_depth = _nonnegative_int(max_depth, 2)
    effective_max_requests = min(_nonnegative_int(max_requests, 30), HARD_MAX_REQUESTS)
    effective_rate_delay = _nonnegative_float(rate_delay_seconds, 0.5)
    effective_max_links_per_page = _nonnegative_int(max_links_per_page, 200)

    log_event(f"workflow: safe_bounded_crawl start target={target}")
    scope = check_scope(target)

    log_event(
        f"workflow: safe_bounded_crawl scope target={target} "
        f"in_scope={scope.get('in_scope')} hostname={scope.get('hostname')}"
    )

    if not scope.get("in_scope"):
        return {
            "target": target,
            "stopped": True,
            "reason": "Target is not in scope.",
            "scope": scope,
            "crawled_pages": [],
            "skipped_urls": [],
            "inventory_candidates": [],
            "observations": [],
            "summary": {
                "crawled_page_count": 0,
                "inventory_candidate_count": 0,
                "skipped_url_count": 0,
                "max_pages": effective_max_pages,
                "max_depth": effective_max_depth,
                "max_requests": effective_max_requests,
                "hard_max_requests": HARD_MAX_REQUESTS,
                "rate_delay_seconds": effective_rate_delay,
                "max_links_per_page": effective_max_links_per_page,
            },
            "safety": _safety(0, scan_level="blocked"),
        }

    target_url = _target_url(target)
    target_hostname = (scope.get("hostname") or _hostname(target_url)).lower()
    queue = CrawlQueue(
        base_url=target_url,
        max_pages=effective_max_pages,
        max_depth=effective_max_depth,
        max_requests=effective_max_requests,
        allowed_hosts=["*"],
    )

    seed = queue.add(target_url, depth=0, source="seed")
    skipped_urls = []
    if not seed.get("accepted"):
        skipped_urls.append(seed)

    crawled_pages = []
    observations = []
    inventory_candidates = []
    seen_inventory_urls = set()
    requests_sent = 0

    while requests_sent < effective_max_requests and len(crawled_pages) < effective_max_pages:
        queue_item = queue.pop()
        if queue_item is None:
            break

        page_url = queue_item.get("url", "")
        depth = queue_item.get("depth", 0)

        if not _same_host_or_in_scope(page_url, target_hostname):
            skipped_urls.append(
                {
                    "accepted": False,
                    "url": page_url,
                    "depth": depth,
                    "source": queue_item.get("source", ""),
                    "reason": "URL is outside target host and configured scope.",
                }
            )
            continue

        if requests_sent > 0 and effective_rate_delay > 0:
            time.sleep(effective_rate_delay)

        log_event(f"workflow: safe_bounded_crawl request_start url={page_url} depth={depth}")
        probe, helper_called = _safe_http_probe(page_url)
        if helper_called and not probe.get("blocked"):
            requests_sent += 1

        log_event(
            f"workflow: safe_bounded_crawl request_done url={page_url} "
            f"depth={depth} blocked={probe.get('blocked')} "
            f"status={probe.get('status_code')} error={probe.get('error')}"
        )

        crawled_pages.append(
            {
                "url": page_url,
                "depth": depth,
                "status_code": probe.get("status_code"),
                "content_type": _content_type(probe),
                "body_size": probe.get("body_size"),
            }
        )

        if probe.get("error"):
            observations.append(_base_observation(page_url, probe, "request_error", depth))
            continue

        if probe.get("blocked"):
            observations.append(_base_observation(page_url, probe, "blocked", depth))
            continue

        content_type = _content_type(probe)
        if content_type not in ALLOWED_HTML_CONTENT_TYPES:
            observations.append(
                _base_observation(
                    page_url,
                    probe,
                    "unsupported_content_type",
                    depth,
                    error=f"Unsupported content type for bounded crawl parsing: {content_type or 'missing'}.",
                )
            )
            continue

        html_text = _probe_body_text(probe)
        if not html_text:
            observations.append(
                _base_observation(
                    page_url,
                    probe,
                    "parse_error",
                    depth,
                    error="HTML response body was not available.",
                )
            )
            continue

        extracted = extract_html_links(
            html_text,
            base_url=page_url,
            max_links=effective_max_links_per_page,
        )
        if not extracted.get("ok"):
            observations.append(
                _base_observation(
                    page_url,
                    probe,
                    "parse_error",
                    depth,
                    error=extracted.get("error", "HTML link extraction failed."),
                )
            )
            continue

        observations.append(
            {
                **_base_observation(page_url, probe, "parsed", depth),
                "link_count": len(extracted.get("links", [])),
                "script_count": len(extracted.get("scripts", [])),
                "skipped_extracted_count": len(extracted.get("skipped", [])),
            }
        )

        for skipped in extracted.get("skipped", []):
            skipped_urls.append(
                {
                    **skipped,
                    "source_page": page_url,
                    "depth": depth + 1,
                }
            )

        for link in extracted.get("links", []):
            normalized_url = link.get("normalized_url", "")
            if not _same_host_or_in_scope(normalized_url, target_hostname):
                skipped_urls.append(
                    {
                        "accepted": False,
                        "url": normalized_url,
                        "raw_url": link.get("raw_url"),
                        "depth": depth + 1,
                        "source": "html_link",
                        "reason": "URL is outside target host and configured scope.",
                    }
                )
                continue

            _append_candidate(
                candidates=inventory_candidates,
                seen_inventory_urls=seen_inventory_urls,
                target=target,
                raw_url=link.get("raw_url", normalized_url),
                normalized_url=normalized_url,
                source="html_link",
                discovered_from=page_url,
                probe=probe,
            )

            queue_result = queue.add(normalized_url, depth=depth + 1, source="html_link")
            if not queue_result.get("accepted"):
                skipped_urls.append(queue_result)

        for script in extracted.get("scripts", []):
            normalized_url = script.get("normalized_url", "")
            if not _same_host_or_in_scope(normalized_url, target_hostname):
                skipped_urls.append(
                    {
                        "accepted": False,
                        "url": normalized_url,
                        "raw_url": script.get("raw_url"),
                        "depth": depth,
                        "source": "html_script_tag",
                        "reason": "Script URL is outside target host and configured scope.",
                    }
                )
                continue

            _append_candidate(
                candidates=inventory_candidates,
                seen_inventory_urls=seen_inventory_urls,
                target=target,
                raw_url=script.get("raw_url", normalized_url),
                normalized_url=normalized_url,
                source="html_script_tag",
                discovered_from=page_url,
                probe=probe,
            )

    summary = {
        "crawled_page_count": len(crawled_pages),
        "inventory_candidate_count": len(inventory_candidates),
        "skipped_url_count": len(skipped_urls),
        "queue_summary": queue.summary(),
        "max_pages": effective_max_pages,
        "max_depth": effective_max_depth,
        "max_requests": effective_max_requests,
        "hard_max_requests": HARD_MAX_REQUESTS,
        "rate_delay_seconds": effective_rate_delay,
        "max_links_per_page": effective_max_links_per_page,
    }

    log_event(
        f"workflow: safe_bounded_crawl complete target={target} "
        f"requests_sent={requests_sent} pages={len(crawled_pages)} "
        f"candidates={len(inventory_candidates)}"
    )

    return {
        "target": target,
        "stopped": False,
        "scope": scope,
        "crawled_pages": crawled_pages,
        "skipped_urls": skipped_urls,
        "inventory_candidates": inventory_candidates,
        "observations": observations,
        "summary": summary,
        "safety": _safety(requests_sent),
    }
