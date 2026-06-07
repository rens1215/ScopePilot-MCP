from urllib.parse import urlsplit, urlunsplit
from xml.etree import ElementTree

from tools.http_result_utils import (
    base_http_observation,
    get_content_type,
    headers_summary,
    probe_body_text,
    safe_http_probe_call,
)
from tools.inventory_candidate_builder import build_validated_inventory_candidate
from tools.logger import log_event
from tools.result_schema import build_blocked_result, build_workflow_result
from tools.safety_metadata import build_safety_metadata
from tools.scope_guard import check_scope
from tools.url_normalizer import normalize_url

try:
    from tools.http_probe import http_probe
except ImportError:
    http_probe = None


SITEMAP_PATH = "/sitemap.xml"
DEFAULT_MAX_SITEMAP_BYTES = 1024 * 1024
DEFAULT_MAX_URLS = 100


def _safety(requests_sent: int, scan_level: str = "low-risk") -> dict:
    return build_safety_metadata(requests_sent=requests_sent, scan_level=scan_level)


def _target_origin(target: str) -> str:
    candidate = target if "://" in target else f"https://{target}"
    parts = urlsplit(candidate)
    scheme = (parts.scheme or "https").lower()
    netloc = parts.netloc or parts.path
    return urlunsplit((scheme, netloc, "", "", ""))


def _sitemap_url(target: str) -> str:
    return f"{_target_origin(target).rstrip('/')}{SITEMAP_PATH}"


def _safe_http_probe(sitemap_url: str) -> tuple[dict, bool]:
    """
    Call the low-risk HTTP helper and normalize failures into a probe dict.

    The workflow sends at most one request to /sitemap.xml after scope passes.
    Helper exceptions or malformed return values become request_error
    observations so the workflow does not crash on transient network/helper
    failures.
    """
    return safe_http_probe_call(sitemap_url, probe_func=http_probe)


def _extract_sitemap_locations(xml_text: str, max_urls: int) -> list[str]:
    root = ElementTree.fromstring(xml_text)
    locations = []

    for element in root.iter():
        tag_name = element.tag.rsplit("}", 1)[-1].lower()
        if tag_name != "loc":
            continue

        location = (element.text or "").strip()
        if not location:
            continue

        locations.append(location)
        if len(locations) >= max_urls:
            break

    return locations


def _same_host_or_in_scope(normalized_url: str, target_hostname: str) -> bool:
    candidate_hostname = (urlsplit(normalized_url).hostname or "").lower()
    if candidate_hostname == target_hostname:
        return True

    # Secondary scope check is local policy evaluation only. It does not send
    # requests and protects against cross-scope URLs listed inside sitemap XML.
    try:
        scope = check_scope(normalized_url)
    except Exception:
        return False

    return bool(scope.get("in_scope"))


def _build_candidate(target: str, extracted_url: str, normalized_url: str, probe: dict) -> dict:
    return build_validated_inventory_candidate(
        target=target,
        raw_url=extracted_url,
        normalized_url=normalized_url,
        source="sitemap",
        discovered_by="safe_sitemap_parser_workflow",
        evidence={
            "status_code": probe.get("status_code"),
            "content_type": get_content_type(probe),
            "body_size": probe.get("body_size"),
            "headers_summary": headers_summary(probe.get("headers")),
        },
        notes=(
            "URL extracted from sitemap XML only. The workflow did not request "
            "this extracted URL and does not treat it as vulnerability evidence."
        ),
    )


def _base_observation(sitemap_url: str, probe: dict, status: str, error: str | None = None) -> dict:
    return {
        **base_http_observation(sitemap_url, probe, status, error=error),
        "path": SITEMAP_PATH,
        "source": "sitemap",
    }


def safe_sitemap_parser_workflow(
    target: str,
    max_sitemap_bytes: int = DEFAULT_MAX_SITEMAP_BYTES,
    max_urls: int = DEFAULT_MAX_URLS,
) -> dict:
    """
    Parse an in-scope target's /sitemap.xml into endpoint inventory candidates.

    This is a low-risk sitemap observation/parsing workflow. It checks scope
    before any external request, requests only /sitemap.xml, and never requests
    URLs listed inside the sitemap.

    Safety boundaries:
    - Does not crawl, recurse through unlimited sitemap indexes, fuzz, brute
      force, exploit, or use credentials.
    - Does not save cookies, tokens, secrets, personal data, payment data, or
      complete sensitive response bodies.
    - Limits sitemap XML size and extracted URL count.
    - Converts same-host or in-scope extracted URLs into in-memory inventory
      candidates only.
    """
    log_event(f"workflow: safe_sitemap_parser start target={target}")
    scope = check_scope(target)

    log_event(
        f"workflow: safe_sitemap_parser scope target={target} "
        f"in_scope={scope.get('in_scope')} hostname={scope.get('hostname')}"
    )

    if not scope.get("in_scope"):
        return build_blocked_result(
            target=target,
            reason="Target is not in scope.",
            scope=scope,
            sitemap_url=None,
            extracted_urls=[],
            skipped_urls=[],
            allowed_sitemap_path=SITEMAP_PATH,
        )

    sitemap_url = _sitemap_url(target)
    log_event(f"workflow: safe_sitemap_parser request_start url={sitemap_url}")

    probe, helper_called = _safe_http_probe(sitemap_url)
    requests_sent = 1 if helper_called and not probe.get("blocked") else 0

    log_event(
        f"workflow: safe_sitemap_parser request_done url={sitemap_url} "
        f"blocked={probe.get('blocked')} status={probe.get('status_code')} "
        f"error={probe.get('error')}"
    )

    observations = []
    extracted_urls = []
    skipped_urls = []
    inventory_candidates = []

    if probe.get("error"):
        observations.append(_base_observation(sitemap_url, probe, "request_error"))
    elif probe.get("blocked"):
        observations.append(_base_observation(sitemap_url, probe, "blocked"))
    elif probe.get("status_code") in (404, 410):
        observations.append(_base_observation(sitemap_url, probe, "not_found"))
    else:
        body_size = probe.get("body_size")
        if isinstance(body_size, int) and body_size > max_sitemap_bytes:
            observations.append(
                _base_observation(
                    sitemap_url,
                    probe,
                    "oversized",
                    error="Sitemap body_size exceeds max_sitemap_bytes.",
                )
            )
        else:
            xml_text = probe_body_text(probe)
            xml_size = len(xml_text.encode("utf-8"))

            if not xml_text:
                observations.append(
                    _base_observation(
                        sitemap_url,
                        probe,
                        "parse_error",
                        error="Sitemap response body was not available.",
                    )
                )
            elif xml_size > max_sitemap_bytes:
                observations.append(
                    _base_observation(
                        sitemap_url,
                        probe,
                        "oversized",
                        error="Sitemap XML exceeds max_sitemap_bytes.",
                    )
                )
            else:
                try:
                    locations = _extract_sitemap_locations(xml_text, max_urls)
                except ElementTree.ParseError as error:
                    observations.append(
                        _base_observation(
                            sitemap_url,
                            probe,
                            "parse_error",
                            error=f"Invalid sitemap XML: {error}",
                        )
                    )
                else:
                    target_hostname = (scope.get("hostname") or "").lower()

                    for location in locations:
                        normalized = normalize_url(location, base_url=sitemap_url)
                        if not normalized.get("ok"):
                            skipped_urls.append(
                                {
                                    "url": location,
                                    "reason": normalized.get("error", "URL normalization failed."),
                                }
                            )
                            continue

                        normalized_url = normalized.get("normalized_url", "")
                        if not _same_host_or_in_scope(normalized_url, target_hostname):
                            skipped_urls.append(
                                {
                                    "url": location,
                                    "normalized_url": normalized_url,
                                    "reason": "URL is outside target host and configured scope.",
                                }
                            )
                            continue

                        extracted_urls.append(normalized_url)
                        inventory_candidates.append(
                            _build_candidate(target, location, normalized_url, probe)
                        )

                    observations.append(
                        {
                            **_base_observation(sitemap_url, probe, "parsed"),
                            "extracted_url_count": len(extracted_urls),
                            "skipped_url_count": len(skipped_urls),
                            "max_urls": max_urls,
                            "max_sitemap_bytes": max_sitemap_bytes,
                        }
                    )

    log_event(
        f"workflow: safe_sitemap_parser complete target={target} "
        f"requests_sent={requests_sent} candidates={len(inventory_candidates)}"
    )

    return build_workflow_result(
        target=target,
        stopped=False,
        scope=scope,
        observations=observations,
        inventory_candidates=inventory_candidates,
        summary={
            "sitemap_requested": True,
            "inventory_candidate_count": len(inventory_candidates),
            "extracted_url_count": len(extracted_urls),
            "skipped_url_count": len(skipped_urls),
        },
        safety=_safety(requests_sent),
        sitemap_url=sitemap_url,
        extracted_urls=extracted_urls,
        skipped_urls=skipped_urls,
        allowed_sitemap_path=SITEMAP_PATH,
    )
