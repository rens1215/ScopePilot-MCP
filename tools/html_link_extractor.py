from html.parser import HTMLParser

from tools.url_normalizer import normalize_url


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.items = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered_tag = tag.lower()
        if lowered_tag not in {"a", "script"}:
            return

        target_attr = "href" if lowered_tag == "a" else "src"
        for name, value in attrs:
            if name.lower() == target_attr and value:
                self.items.append(
                    {
                        "raw_url": value.strip(),
                        "source_tag": lowered_tag,
                    }
                )


def _positive_int(value: int, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default

    return max(parsed, 0)


def _result(
    ok: bool,
    links: list[dict] | None = None,
    scripts: list[dict] | None = None,
    skipped: list[dict] | None = None,
    error: str = "",
) -> dict:
    if links is None:
        links = []
    if scripts is None:
        scripts = []
    if skipped is None:
        skipped = []

    return {
        "ok": ok,
        "links": links,
        "scripts": scripts,
        "skipped": skipped,
        "count": len(links) + len(scripts),
        "error": error,
    }


def extract_html_links(
    html_text: str,
    base_url: str | None = None,
    max_links: int = 500,
) -> dict:
    """
    Extract safe crawl candidates from local HTML text.

    This helper performs local parsing only. It does not send HTTP requests,
    call workflows, submit forms, execute JavaScript, parse onclick handlers,
    evaluate dynamic routes, modify state, or use credentials. It extracts only
    <a href="..."> and <script src="..."> values, normalizes them with
    normalize_url, de-duplicates by normalized URL, and returns structured
    candidates for later bounded crawler queue policy.
    """
    if not isinstance(html_text, str):
        return _result(False, error="html_text must be a string.")

    effective_max_links = _positive_int(max_links, 500)
    parser = _LinkParser()
    parser.feed(html_text)

    links = []
    scripts = []
    skipped = []
    seen = set()

    for item in parser.items:
        if len(links) + len(scripts) >= effective_max_links:
            skipped.append(
                {
                    "raw_url": item["raw_url"],
                    "source_tag": item["source_tag"],
                    "reason": "max_links limit reached.",
                }
            )
            continue

        normalized = normalize_url(item["raw_url"], base_url=base_url)
        if not normalized.get("ok"):
            skipped.append(
                {
                    "raw_url": item["raw_url"],
                    "source_tag": item["source_tag"],
                    "reason": normalized.get("error", "URL normalization failed."),
                }
            )
            continue

        normalized_url = normalized.get("normalized_url", "")
        if normalized_url in seen:
            skipped.append(
                {
                    "raw_url": item["raw_url"],
                    "normalized_url": normalized_url,
                    "source_tag": item["source_tag"],
                    "reason": "duplicate normalized URL.",
                }
            )
            continue

        seen.add(normalized_url)
        output_item = {
            "raw_url": item["raw_url"],
            "normalized_url": normalized_url,
            "source_tag": item["source_tag"],
        }

        if item["source_tag"] == "script":
            scripts.append(output_item)
        else:
            links.append(output_item)

    return _result(True, links=links, scripts=scripts, skipped=skipped)
