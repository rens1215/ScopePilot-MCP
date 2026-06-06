from collections import Counter
from copy import deepcopy
from typing import Any


SAFE_EVIDENCE_KEYS = {"status_code", "content_type", "body_size", "headers_summary"}

DEFAULT_SAFETY = {
    "requests_sent": 0,
    "fuzzing": False,
    "bruteforce": False,
    "exploitation": False,
    "crawling": False,
    "credentialed_request": False,
}


def _safe_evidence(evidence: dict | None) -> dict:
    if not isinstance(evidence, dict):
        evidence = {}

    # Only keep metadata-shaped evidence. Never store bodies, cookies, tokens,
    # secrets, personal data, payment data, or raw credential material here.
    return {
        "status_code": evidence.get("status_code"),
        "content_type": evidence.get("content_type", ""),
        "body_size": evidence.get("body_size"),
        "headers_summary": evidence.get("headers_summary", {})
        if isinstance(evidence.get("headers_summary", {}), dict)
        else {},
    }


def build_inventory_item(
    target: str,
    url: str,
    normalized_url: str,
    source: str,
    method_guess: str = "GET",
    endpoint_type: str = "unknown",
    priority: str = "low",
    confidence: str = "low",
    discovered_by: str = "",
    evidence: dict | None = None,
    recommended_next_skill: str = "",
    recommended_next_steps: list[str] | None = None,
    notes: str = "",
) -> dict[str, Any]:
    """
    Build an in-memory endpoint inventory item.

    This function does not send requests, call workflows, execute tools, write
    to data/, or modify target state. It only creates a structured dictionary
    from caller-provided URL metadata.

    Sensitive data boundary: evidence is reduced to safe metadata keys only.
    Do not pass cookies, tokens, secrets, personal data, payment data, or full
    response bodies into inventory items.
    """
    if recommended_next_steps is None:
        recommended_next_steps = []

    return {
        "target": target,
        "url": url,
        "normalized_url": normalized_url,
        "source": source,
        "method_guess": method_guess,
        "endpoint_type": endpoint_type,
        "priority": priority,
        "confidence": confidence,
        "discovered_by": discovered_by,
        "evidence": _safe_evidence(evidence),
        "safety": deepcopy(DEFAULT_SAFETY),
        "recommended_next_skill": recommended_next_skill,
        "recommended_next_steps": list(recommended_next_steps),
        "notes": notes,
    }


def dedupe_inventory_items(items: list[dict]) -> list[dict]:
    """
    De-duplicate in-memory inventory items by normalized_url.

    The first item wins to preserve original discovery metadata. This function
    performs no file writes, sends no requests, and calls no workflows.
    """
    deduped = []
    seen = set()

    for item in items:
        if not isinstance(item, dict):
            continue

        normalized_url = item.get("normalized_url")
        if not normalized_url:
            continue

        if normalized_url in seen:
            continue

        seen.add(normalized_url)
        deduped.append(item)

    return deduped


def summarize_inventory(items: list[dict]) -> dict:
    """
    Summarize in-memory inventory items by source, endpoint_type, and priority.

    This is local aggregation only. It does not write to data/, send requests,
    call workflows, or infer that any endpoint is vulnerable.
    """
    safe_items = [item for item in items if isinstance(item, dict)]

    by_source = Counter(item.get("source", "unknown") or "unknown" for item in safe_items)
    by_endpoint_type = Counter(item.get("endpoint_type", "unknown") or "unknown" for item in safe_items)
    by_priority = Counter(item.get("priority", "low") or "low" for item in safe_items)

    return {
        "total_items": len(safe_items),
        "by_source": dict(by_source),
        "by_endpoint_type": dict(by_endpoint_type),
        "by_priority": dict(by_priority),
    }
