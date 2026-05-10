import json
import fnmatch
from urllib.parse import urlparse
from pathlib import Path


SCOPE_FILE = Path(__file__).resolve().parent.parent / "config" / "scope.json"


def load_scope() -> dict:
    with open(SCOPE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_hostname(target: str) -> str:
    """
    Accepts:
    - https://api.example.com/path
    - api.example.com
    Returns:
    - api.example.com
    """
    if "://" not in target:
        target = "https://" + target

    parsed = urlparse(target)
    return parsed.hostname.lower() if parsed.hostname else ""


def is_domain_allowed(hostname: str, allowed_patterns: list[str]) -> bool:
    for pattern in allowed_patterns:
        pattern = pattern.lower()

        if pattern.startswith("*."):
            root = pattern[2:]
            if hostname == root or hostname.endswith("." + root):
                return True

        if fnmatch.fnmatch(hostname, pattern):
            return True

    return False


def is_domain_blocked(hostname: str, blocked_patterns: list[str]) -> bool:
    for pattern in blocked_patterns:
        pattern = pattern.lower()
        if fnmatch.fnmatch(hostname, pattern):
            return True
    return False


def check_scope(target: str) -> dict:
    scope = load_scope()
    hostname = normalize_hostname(target)

    if not hostname:
        return {
            "target": target,
            "hostname": None,
            "in_scope": False,
            "reason": "Invalid target or hostname could not be parsed.",
            "allowed_scan_level": "forbidden"
        }

    blocked = is_domain_blocked(hostname, scope.get("blocked_domains", []))
    allowed = is_domain_allowed(hostname, scope.get("allowed_domains", []))

    if blocked:
        return {
            "target": target,
            "hostname": hostname,
            "in_scope": False,
            "reason": "Target matches blocked domain rule.",
            "allowed_scan_level": "forbidden"
        }

    if not allowed:
        return {
            "target": target,
            "hostname": hostname,
            "in_scope": False,
            "reason": "Target does not match allowed scope.",
            "allowed_scan_level": "forbidden"
        }

    return {
        "target": target,
        "hostname": hostname,
        "in_scope": True,
        "reason": "Target is allowed by scope configuration.",
        "allowed_scan_level": scope.get("allowed_scan_level", "passive_or_light"),
        "max_rps": scope.get("max_rps", 1),
        "program": scope.get("program")
    }