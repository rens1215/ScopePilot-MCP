import dns.resolver
from tools.scope_guard import check_scope


def dns_lookup(target: str) -> dict:
    scope = check_scope(target)

    if not scope["in_scope"]:
        return {
            "target": target,
            "blocked": True,
            "scope": scope,
            "records": {}
        }

    hostname = scope["hostname"]
    result = {
        "target": target,
        "hostname": hostname,
        "blocked": False,
        "scope": scope,
        "records": {
            "A": [],
            "AAAA": [],
            "CNAME": [],
            "MX": [],
            "TXT": []
        }
    }

    for record_type in result["records"].keys():
        try:
            answers = dns.resolver.resolve(hostname, record_type)
            result["records"][record_type] = [str(rdata) for rdata in answers]
        except Exception as e:
            result["records"][record_type] = []
            result.setdefault("errors", {})[record_type] = str(e)

    return result