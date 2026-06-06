from urllib.parse import urlsplit


STATIC_EXTENSIONS = (
    ".css",
    ".js",
    ".mjs",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
)

AUTH_MARKERS = ("login", "signin", "signup", "auth", "oauth", "sso", "callback", "password")
ADMIN_MARKERS = ("admin", "dashboard", "console", "manage", "management")
DOC_MARKERS = ("docs", "documentation", "swagger", "openapi", "api-docs", "redoc")


def _validation_result(
    valid: bool,
    endpoint_type: str = "unknown",
    priority: str = "low",
    confidence: str = "low",
    reason: str = "",
    recommended_next_skill: str = "passive_recon",
    false_positive_notes: list[str] | None = None,
) -> dict:
    if false_positive_notes is None:
        false_positive_notes = []

    return {
        "valid": valid,
        "endpoint_type": endpoint_type,
        "priority": priority,
        "confidence": confidence,
        "reason": reason,
        "recommended_next_skill": recommended_next_skill,
        "false_positive_notes": false_positive_notes,
    }


def validate_inventory_item(item: dict) -> dict:
    """
    Validate and conservatively classify an endpoint inventory item.

    This validator only classifies endpoint type, priority, confidence, and
    noise-reduction notes. It does not send requests, execute payloads, call
    workflows, modify data, or claim that any vulnerability exists.
    """
    if not isinstance(item, dict):
        return _validation_result(False, reason="Inventory item must be a dictionary.")

    normalized_url = item.get("normalized_url", "")
    if not isinstance(normalized_url, str) or not normalized_url:
        return _validation_result(False, reason="Inventory item is missing normalized_url.")

    parsed = urlsplit(normalized_url)
    path = parsed.path.lower()
    hostname = (parsed.hostname or "").lower()

    notes = [
        "Inventory classification is not vulnerability confirmation.",
        "Manual validation and risk approval may be required before deeper testing.",
    ]

    if path.endswith(STATIC_EXTENSIONS):
        return _validation_result(
            True,
            endpoint_type="static_asset",
            priority="low",
            confidence="high",
            reason="Path ends with a common static asset extension.",
            recommended_next_skill="passive_recon",
            false_positive_notes=notes,
        )

    if any(marker in path for marker in AUTH_MARKERS):
        return _validation_result(
            True,
            endpoint_type="auth_page",
            priority="high",
            confidence="medium",
            reason="Path contains authentication-related terms.",
            recommended_next_skill="risk_gate",
            false_positive_notes=notes,
        )

    if any(marker in path for marker in ADMIN_MARKERS):
        return _validation_result(
            True,
            endpoint_type="admin_candidate",
            priority="high",
            confidence="medium",
            reason="Path contains admin or management-related terms.",
            recommended_next_skill="risk_gate",
            false_positive_notes=notes,
        )

    if path.startswith("/api") or "/api/" in path or hostname.startswith("api."):
        return _validation_result(
            True,
            endpoint_type="api",
            priority="medium",
            confidence="medium",
            reason="URL shape suggests an API endpoint.",
            recommended_next_skill="passive_recon",
            false_positive_notes=notes,
        )

    if any(marker in path for marker in DOC_MARKERS):
        return _validation_result(
            True,
            endpoint_type="documentation",
            priority="medium",
            confidence="medium",
            reason="Path contains documentation-related terms.",
            recommended_next_skill="passive_recon",
            false_positive_notes=notes,
        )

    if path in ("", "/") or "." not in path.rsplit("/", 1)[-1]:
        return _validation_result(
            True,
            endpoint_type="frontend",
            priority="medium",
            confidence="low",
            reason="URL appears to be a frontend route or page.",
            recommended_next_skill="passive_recon",
            false_positive_notes=notes,
        )

    return _validation_result(
        True,
        endpoint_type="unknown",
        priority="low",
        confidence="low",
        reason="Endpoint did not match a stronger conservative classification rule.",
        recommended_next_skill="passive_recon",
        false_positive_notes=notes,
    )
