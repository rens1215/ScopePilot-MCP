from urllib.parse import urlsplit, urlunsplit

from tools.http_result_utils import base_http_observation, get_content_type, headers_summary, safe_http_probe_call
from tools.inventory_candidate_builder import build_validated_inventory_candidate
from tools.result_schema import build_blocked_result, build_workflow_result
from tools.safety_metadata import build_safety_metadata
from tools.scope_guard import check_scope
from tools.url_normalizer import normalize_url
from tools.logger import log_event

try:
    from tools.http_probe import http_probe
except ImportError:
    http_probe = None


METADATA_PATHS = (
    ("/robots.txt", "robots"),
    ("/.well-known/security.txt", "security_txt"),
    ("/sitemap.xml", "sitemap"),
)


def _safety(requests_sent: int, scan_level: str = "low-risk") -> dict:
    return build_safety_metadata(requests_sent=requests_sent, scan_level=scan_level)


def _target_origin(target: str) -> str:
    candidate = target if "://" in target else f"https://{target}"
    parts = urlsplit(candidate)
    scheme = (parts.scheme or "https").lower()
    netloc = parts.netloc or parts.path
    return urlunsplit((scheme, netloc, "", "", ""))


def _metadata_url(target: str, path: str) -> str:
    return f"{_target_origin(target).rstrip('/')}{path}"


def _build_candidate(target: str, metadata_url: str, source: str, probe: dict) -> dict:
    normalized = normalize_url(metadata_url)
    normalized_url = normalized.get("normalized_url") if normalized.get("ok") else metadata_url

    return build_validated_inventory_candidate(
        target=target,
        raw_url=metadata_url,
        normalized_url=normalized_url,
        source=source,
        discovered_by="safe_robots_securitytxt_workflow",
        evidence={
            "status_code": probe.get("status_code"),
            "content_type": get_content_type(probe),
            "body_size": probe.get("body_size"),
            "headers_summary": headers_summary(probe.get("headers")),
        },
        notes=(
            "Public metadata observation only. Missing files are observations, "
            "not workflow errors. Do not treat robots.txt Disallow paths as scan authorization."
        ),
    )


def _safe_http_probe(metadata_url: str) -> tuple[dict, bool]:
    """
    Call the low-risk HTTP helper and normalize failures into a probe dict.

    This keeps the workflow fail-closed for one metadata path: helper
    exceptions or malformed return values become request_error observations
    instead of crashing the whole workflow.
    """
    return safe_http_probe_call(metadata_url, probe_func=http_probe)


def _base_observation(path: str, source: str, metadata_url: str, probe: dict, status: str) -> dict:
    return {
        **base_http_observation(metadata_url, probe, status),
        "path": path,
        "source": source,
    }


def safe_robots_securitytxt_workflow(target: str) -> dict:
    """
    Observe public metadata files on an in-scope target.

    This is a low-risk metadata observation workflow. It checks scope first and
    then requests only these fixed public paths:
    /robots.txt, /.well-known/security.txt, and /sitemap.xml.

    Safety boundaries:
    - Does not scan paths listed inside robots.txt.
    - Does not treat Disallow entries as authorization to scan.
    - Does not crawl, recurse, fuzz, brute force, exploit, or use credentials.
    - Does not save cookies, tokens, secrets, personal data, payment data, or
      full sensitive response bodies.
    - Builds in-memory inventory candidate items from non-sensitive metadata.
    """
    log_event(f"workflow: safe_robots_securitytxt start target={target}")
    scope = check_scope(target)

    log_event(
        f"workflow: safe_robots_securitytxt scope target={target} "
        f"in_scope={scope.get('in_scope')} hostname={scope.get('hostname')}"
    )

    if not scope.get("in_scope"):
        return build_blocked_result(
            target=target,
            reason="Target is not in scope.",
            scope=scope,
            allowed_metadata_paths=[path for path, _source in METADATA_PATHS],
        )

    observations = []
    inventory_candidates = []
    requests_sent = 0

    for path, source in METADATA_PATHS:
        metadata_url = _metadata_url(target, path)
        log_event(f"workflow: safe_robots_securitytxt request_start url={metadata_url}")

        probe, helper_called = _safe_http_probe(metadata_url)

        if helper_called and not probe.get("blocked"):
            requests_sent += 1

        log_event(
            f"workflow: safe_robots_securitytxt request_done url={metadata_url} "
            f"blocked={probe.get('blocked')} status={probe.get('status_code')} "
            f"error={probe.get('error')}"
        )

        observation_status = "observed"
        if probe.get("error"):
            observation_status = "request_error"
        elif probe.get("status_code") in (404, 410):
            observation_status = "not_found"
        elif probe.get("blocked"):
            observation_status = "blocked"

        observation = _base_observation(path, source, metadata_url, probe, observation_status)
        observations.append(observation)

        candidate = _build_candidate(target, metadata_url, source, probe)
        inventory_candidates.append(candidate)

    log_event(
        f"workflow: safe_robots_securitytxt complete target={target} "
        f"requests_sent={requests_sent} candidates={len(inventory_candidates)}"
    )

    return build_workflow_result(
        target=target,
        stopped=False,
        scope=scope,
        observations=observations,
        inventory_candidates=inventory_candidates,
        summary={
            "metadata_paths_checked": len(METADATA_PATHS),
            "inventory_candidate_count": len(inventory_candidates),
            "not_found_count": sum(1 for item in observations if item.get("status") == "not_found"),
        },
        safety=_safety(requests_sent),
        allowed_metadata_paths=[path for path, _source in METADATA_PATHS],
    )
