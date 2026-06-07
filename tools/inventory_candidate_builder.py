from tools.endpoint_inventory import build_inventory_item
from tools.http_result_utils import headers_summary
from validators.inventory_validator import validate_inventory_item


SAFE_EVIDENCE_KEYS = {
    "status_code",
    "content_type",
    "body_size",
    "headers_summary",
    "source",
    "discovered_from",
    "method_guess",
}

SENSITIVE_EVIDENCE_KEYS = {
    "body",
    "text",
    "response_text",
    "content",
    "cookie",
    "set-cookie",
    "authorization",
    "token",
    "secret",
    "api-key",
    "apikey",
    "personal_data",
    "payment_data",
}

SENSITIVE_EVIDENCE_MARKERS = {
    "token",
    "secret",
    "api-key",
    "apikey",
}


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in SENSITIVE_EVIDENCE_KEYS:
        return True

    return any(marker in lowered for marker in SENSITIVE_EVIDENCE_MARKERS)


def sanitize_inventory_evidence(evidence: dict | None) -> dict:
    """
    Reduce caller-provided evidence to safe inventory metadata.

    This helper performs local dictionary filtering only. It does not call
    http_probe, send HTTP or other external requests, call workflows, write to
    data/, save findings, execute tools, exploit, fuzz, brute force, submit
    forms, use credentials, or perform state-changing actions.

    Safety boundary: full response bodies, cookies, tokens, secrets, personal
    data, payment data, credential material, and sensitive headers are removed.
    The result is inventory metadata, not vulnerability proof.
    """
    if not isinstance(evidence, dict):
        return {}

    sanitized = {}
    for key, value in evidence.items():
        key_name = str(key)
        lowered = key_name.lower()

        # Fail closed on sensitive-looking keys even if a future caller happens
        # to use a name that also resembles an allowlisted metadata field.
        if _is_sensitive_key(lowered):
            continue

        if lowered not in SAFE_EVIDENCE_KEYS:
            continue

        if lowered == "headers_summary":
            sanitized["headers_summary"] = headers_summary(value if isinstance(value, dict) else {})
        else:
            sanitized[lowered] = value

    return sanitized


def build_validated_inventory_candidate(
    target: str,
    raw_url: str,
    normalized_url: str,
    source: str,
    discovered_by: str,
    evidence: dict | None = None,
    notes: str = "",
) -> dict:
    """
    Build and conservatively classify an inventory candidate.

    This helper creates inventory candidate data only. It does not send
    requests, call http_probe, call workflows, save findings, write to data/,
    execute tools, exploit, fuzz, brute force, test credentials, submit forms,
    perform state-changing actions, or confirm vulnerabilities. Validator output
    is conservative triage metadata, not proof of impact.
    """
    safe_evidence = sanitize_inventory_evidence(evidence)
    safe_raw_url = str(raw_url or "")
    safe_normalized_url = str(normalized_url or "")
    safe_notes = str(notes or "")

    item = build_inventory_item(
        target=str(target or ""),
        url=safe_raw_url,
        normalized_url=safe_normalized_url,
        source=str(source or "unknown"),
        method_guess=str(safe_evidence.get("method_guess", "GET") or "GET"),
        discovered_by=str(discovered_by or ""),
        evidence=safe_evidence,
        notes=safe_notes,
    )

    # build_inventory_item intentionally keeps a narrow legacy evidence shape.
    # v0.5's shared helper preserves the sanitized metadata fields requested by
    # the standardization layer while still using build_inventory_item for the
    # base candidate schema.
    item["evidence"] = safe_evidence

    validation = validate_inventory_item(item)
    item["validator_result"] = validation
    item["endpoint_type"] = validation.get("endpoint_type", "unknown")
    item["priority"] = validation.get("priority", "low")
    item["confidence"] = validation.get("confidence", "low")
    item["recommended_next_skill"] = validation.get("recommended_next_skill", "")

    return item
