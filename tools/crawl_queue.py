from collections import deque
from fnmatch import fnmatch
from urllib.parse import urlsplit

from tools.url_normalizer import normalize_url


def _nonnegative_int(value: int, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default

    return max(parsed, 0)


def _hostname(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _host_matches(hostname: str, pattern: str) -> bool:
    lowered_pattern = pattern.lower()
    if lowered_pattern.startswith("*."):
        root = lowered_pattern[2:]
        return hostname == root or hostname.endswith(f".{root}")

    return fnmatch(hostname, lowered_pattern)


class CrawlQueue:
    """
    Manage bounded crawler queue policy without performing crawling.

    This class does not send HTTP requests, call workflows, call http_probe, use
    credentials, submit forms, execute JavaScript, fuzz, brute force, exploit,
    or change target state. It only normalizes candidate URLs and enforces local
    queue limits: same-host/same-scope filtering, de-duplication, max_depth,
    max_pages, and max_requests.
    """

    def __init__(
        self,
        base_url: str,
        max_pages: int = 100,
        max_depth: int = 2,
        max_requests: int = 100,
        allowed_hosts: list[str] | None = None,
    ) -> None:
        self.base_url = base_url
        self.max_pages = _nonnegative_int(max_pages, 100)
        self.max_depth = _nonnegative_int(max_depth, 2)
        self.max_requests = _nonnegative_int(max_requests, 100)

        normalized_base = normalize_url(base_url)
        self.normalized_base_url = normalized_base.get("normalized_url", "") if normalized_base.get("ok") else ""
        self.base_hostname = _hostname(self.normalized_base_url)

        if allowed_hosts is None:
            allowed_hosts = [self.base_hostname] if self.base_hostname else []
        self.allowed_hosts = [host.lower() for host in allowed_hosts if isinstance(host, str) and host.strip()]

        self._queue = deque()
        self._seen = set()
        self.skipped = []

    def _in_scope(self, normalized_url: str) -> bool:
        hostname = _hostname(normalized_url)
        if not hostname:
            return False

        if hostname == self.base_hostname:
            return True

        return any(_host_matches(hostname, pattern) for pattern in self.allowed_hosts)

    def _skip(self, raw_url: str, depth: int, source: str, reason: str, normalized_url: str = "") -> dict:
        item = {
            "accepted": False,
            "url": normalized_url or raw_url,
            "raw_url": raw_url,
            "depth": depth,
            "source": source,
            "reason": reason,
        }
        self.skipped.append(item)
        return item

    def add(self, url: str, depth: int = 0, source: str = "") -> dict:
        """
        Add a URL candidate to the bounded queue if policy allows it.

        This method performs local URL normalization and queue policy checks
        only. It does not fetch the URL or imply that the URL is safe to test;
        later workflows must still perform scope checks, risk approval, and
        request-limit enforcement before any external action.
        """
        effective_depth = _nonnegative_int(depth, 0)

        normalized = normalize_url(url, base_url=self.normalized_base_url or self.base_url)
        if not normalized.get("ok"):
            return self._skip(url, effective_depth, source, normalized.get("error", "URL normalization failed."))

        normalized_url = normalized.get("normalized_url", "")

        if effective_depth > self.max_depth:
            return self._skip(url, effective_depth, source, "max_depth exceeded.", normalized_url)

        if not self._in_scope(normalized_url):
            return self._skip(url, effective_depth, source, "URL is outside same-host/same-scope policy.", normalized_url)

        if normalized_url in self._seen:
            return self._skip(url, effective_depth, source, "duplicate normalized URL.", normalized_url)

        if len(self._queue) >= self.max_pages:
            return self._skip(url, effective_depth, source, "max_pages limit reached.", normalized_url)

        if len(self._queue) >= self.max_requests:
            return self._skip(url, effective_depth, source, "max_requests limit reached.", normalized_url)

        item = {
            "url": normalized_url,
            "depth": effective_depth,
            "source": source,
        }
        self._queue.append(item)
        self._seen.add(normalized_url)

        return {
            "accepted": True,
            **item,
        }

    def pop(self) -> dict | None:
        """
        Pop the next queued URL without fetching it.

        Returning a queue item is not a network action. The caller is
        responsible for workflow-level scope checks, risk approval, and request
        limits before any external request is sent.
        """
        if not self._queue:
            return None

        return self._queue.popleft()

    def items(self) -> list[dict]:
        """
        Return queued items as local data only.

        This method does not call workflows, send requests, or mutate target
        state.
        """
        return list(self._queue)

    def summary(self) -> dict:
        """
        Summarize local queue state and enforced limits.

        This is queue policy metadata only; it does not represent completed
        requests or vulnerability validation.
        """
        return {
            "queued_count": len(self._queue),
            "skipped_count": len(self.skipped),
            "seen_count": len(self._seen),
            "max_depth": self.max_depth,
            "max_pages": self.max_pages,
            "max_requests": self.max_requests,
        }
