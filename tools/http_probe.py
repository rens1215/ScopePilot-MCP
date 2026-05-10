import httpx
from urllib.parse import urlparse
from tools.scope_guard import check_scope


def normalize_url(target: str) -> str:
    if "://" not in target:
        return "https://" + target
    return target


def extract_title(html: str) -> str | None:
    lower = html.lower()
    start = lower.find("<title>")
    end = lower.find("</title>")

    if start == -1 or end == -1 or end <= start:
        return None

    return html[start + len("<title>"):end].strip()[:200]


def http_probe(target: str) -> dict:
    url = normalize_url(target)
    scope = check_scope(url)

    if not scope["in_scope"]:
        return {
            "target": target,
            "url": url,
            "blocked": True,
            "scope": scope,
            "reason": "Target is not in scope."
        }

    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=10.0,
            headers={
                "User-Agent": "bug-bounty-mcp/0.1 low-risk probe"
            }
        ) as client:
            response = client.get(url)

        content_type = response.headers.get("content-type", "")
        title = None

        if "text/html" in content_type:
            title = extract_title(response.text[:50000])

        return {
            "target": target,
            "url": str(response.url),
            "blocked": False,
            "scope": scope,
            "status_code": response.status_code,
            "final_url": str(response.url),
            "redirect_history": [str(r.url) for r in response.history],
            "headers": dict(response.headers),
            "content_type": content_type,
            "title": title,
            "body_size": len(response.content)
        }

    except Exception as e:
        return {
            "target": target,
            "url": url,
            "blocked": False,
            "scope": scope,
            "error": str(e)
        }