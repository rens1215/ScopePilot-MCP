def classify_endpoint(probe: dict) -> dict:
    title = (probe.get("title") or "").lower()
    content_type = (probe.get("content_type") or "").lower()
    final_url = (probe.get("final_url") or probe.get("url") or "").lower()

    if "application/json" in content_type:
        return {
            "classification": "api",
            "confidence": "high",
            "reason": "JSON response detected."
        }

    if "graphql" in final_url:
        return {
            "classification": "graphql",
            "confidence": "medium",
            "reason": "GraphQL keyword detected in URL."
        }

    admin_keywords = [
        "admin",
        "dashboard",
        "management",
        "control panel",
        "後台",
        "管理"
    ]

    for keyword in admin_keywords:
        if keyword in title or keyword in final_url:
            return {
                "classification": "admin_panel",
                "confidence": "medium",
                "reason": f"Keyword matched: {keyword}"
            }

    auth_keywords = [
        "login",
        "signin",
        "sign in",
        "oauth",
        "auth",
        "登入",
        "註冊"
    ]

    for keyword in auth_keywords:
        if keyword in title or keyword in final_url:
            return {
                "classification": "auth_service",
                "confidence": "medium",
                "reason": f"Keyword matched: {keyword}"
            }

    static_keywords = [
        ".js",
        ".css",
        ".png",
        ".jpg",
        ".jpeg",
        ".svg",
        ".ico",
        ".woff",
        ".woff2"
    ]

    for keyword in static_keywords:
        if keyword in final_url:
            return {
                "classification": "static_asset",
                "confidence": "high",
                "reason": f"Static file extension detected: {keyword}"
            }

    if "text/html" in content_type:
        return {
            "classification": "frontend",
            "confidence": "medium",
            "reason": "HTML response detected."
        }

    return {
        "classification": "unknown",
        "confidence": "low",
        "reason": "No classification rule matched."
    }