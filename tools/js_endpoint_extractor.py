import re
from urllib.parse import urljoin


ABSOLUTE_URL_RE = re.compile(r"https?://[^\s\"'`<>\\)]+", re.IGNORECASE)
QUOTED_VALUE_RE = re.compile(r"""["'`]([^"'`]{1,2048})["'`]""")
UNQUOTED_PATH_RE = re.compile(r"(?<![\w-])/(?:api|v1|v2|graphql|oauth)(?:/[A-Za-z0-9._~:/?#[\]@!$&()*+,;=%-]*)?", re.IGNORECASE)

INTERESTING_PATH_PREFIXES = (
    "/api",
    "/v1",
    "/v2",
    "/graphql",
    "/oauth",
    "api/",
    "v1/",
    "v2/",
    "graphql",
    "oauth/",
    "./api",
    "../api",
    "./v1",
    "../v1",
    "./v2",
    "../v2",
    "./graphql",
    "../graphql",
    "./oauth",
    "../oauth",
)

TRAILING_PUNCTUATION = ".,;:)]}"


def _result(ok: bool, candidates: list[str] | None = None, error: str = "") -> dict:
    if candidates is None:
        candidates = []

    return {
        "ok": ok,
        "candidates": candidates,
        "count": len(candidates),
        "error": error,
    }


def _clean_candidate(value: str) -> str:
    return value.strip().rstrip(TRAILING_PUNCTUATION)


def _looks_like_endpoint(value: str) -> bool:
    lowered = value.lower()

    if lowered.startswith(("http://", "https://")):
        return True

    return lowered.startswith(INTERESTING_PATH_PREFIXES)


def _resolve_candidate(value: str, base_url: str | None) -> str:
    if base_url and not value.lower().startswith(("http://", "https://")):
        return urljoin(base_url, value)
    return value


def extract_js_endpoints(
    js_text: str,
    base_url: str | None = None,
    max_candidates: int = 100,
) -> dict:
    """
    Extract endpoint-like strings from JavaScript source text.

    This helper performs local static text analysis only. It does not send
    requests, call workflows, execute JavaScript, evaluate JavaScript, modify
    target state, or store data. Extracted values are candidates for later
    inventory only and are not vulnerability proof.

    The extractor intentionally keeps a conservative request boundary: callers
    must not automatically request the extracted endpoint candidates.
    """
    if not isinstance(js_text, str):
        return _result(False, error="js_text must be a string.")

    if not isinstance(max_candidates, int) or max_candidates <= 0:
        return _result(False, error="max_candidates must be a positive integer.")

    candidates = []
    seen = set()

    def add_candidate(raw_value: str) -> None:
        if len(candidates) >= max_candidates:
            return

        cleaned = _clean_candidate(raw_value)
        if not cleaned or not _looks_like_endpoint(cleaned):
            return

        resolved = _resolve_candidate(cleaned, base_url)
        if resolved in seen:
            return

        seen.add(resolved)
        candidates.append(resolved)

    # Full URLs may appear outside quoted strings in bundled JavaScript.
    for match in ABSOLUTE_URL_RE.finditer(js_text):
        add_candidate(match.group(0))

    # Quoted strings cover fetch("/api/..."), axios('/v1/...'), GraphQL paths,
    # OAuth paths, and relative route-like strings without executing code.
    for match in QUOTED_VALUE_RE.finditer(js_text):
        add_candidate(match.group(1))

    # A final narrow pass catches unquoted API-like paths in comments or code.
    for match in UNQUOTED_PATH_RE.finditer(js_text):
        add_candidate(match.group(0))

    return _result(True, candidates=candidates)
