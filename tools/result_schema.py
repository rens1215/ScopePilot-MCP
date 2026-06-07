from tools.safety_metadata import build_safety_metadata


def _safe_dict(value) -> dict:
    return dict(value) if isinstance(value, dict) else {}


def _safe_list(value) -> list:
    return list(value) if isinstance(value, list) else []


def build_workflow_result(
    target: str = "",
    stopped: bool = False,
    reason: str = "",
    scope: dict | None = None,
    observations: list[dict] | None = None,
    inventory_candidates: list[dict] | None = None,
    findings: list[dict] | None = None,
    errors: list | None = None,
    warnings: list | None = None,
    summary: dict | None = None,
    safety: dict | None = None,
    **extra_fields,
) -> dict:
    """
    Build a stable workflow result dictionary.

    This helper standardizes local result shape only. It does not execute tools,
    call workflows, call http_probe, send HTTP or other external requests,
    modify findings, build inventory from targets, validate endpoints, submit
    forms, use credentials, or change target state. Extra fields are preserved
    so callers can keep workflow-specific output while gaining standard keys.
    """
    result = dict(extra_fields)

    # Standard keys are assigned explicitly to make the base schema predictable.
    result["target"] = target
    result["stopped"] = bool(stopped)
    result["reason"] = str(reason) if reason is not None else ""
    result["scope"] = _safe_dict(scope)
    result["observations"] = _safe_list(observations)
    result["inventory_candidates"] = _safe_list(inventory_candidates)
    result["findings"] = _safe_list(findings)
    result["errors"] = _safe_list(errors)
    result["warnings"] = _safe_list(warnings)
    result["summary"] = _safe_dict(summary)
    result["safety"] = _safe_dict(safety) if isinstance(safety, dict) else build_safety_metadata()

    return result


def build_blocked_result(
    target: str = "",
    reason: str = "Blocked by policy.",
    scope: dict | None = None,
    **extra_fields,
) -> dict:
    """
    Build a standard stopped result for blocked or out-of-policy actions.

    This helper is local schema construction only. It does not execute tools,
    call workflows, send requests, modify state, or perform security testing.
    The blocked result always reports zero requests and scan_level="blocked".
    """
    return build_workflow_result(
        target=target,
        stopped=True,
        reason=reason,
        scope=scope,
        safety=build_safety_metadata(requests_sent=0, scan_level="blocked"),
        **extra_fields,
    )


def append_observation(result: dict, observation: dict) -> dict:
    """
    Append an observation to a workflow result without dropping existing fields.

    This is a local list-management helper only. It does not execute tools,
    call workflows, send requests, validate vulnerabilities, or modify target
    state. Missing or malformed observations storage is initialized safely.
    """
    if not isinstance(result, dict):
        result = build_workflow_result()

    if not isinstance(result.get("observations"), list):
        result["observations"] = []

    result["observations"].append(dict(observation) if isinstance(observation, dict) else {"value": observation})
    return result


def append_error(result: dict, error: dict | str) -> dict:
    """
    Append an error to a workflow result without dropping existing fields.

    This is a local result-shaping helper only. It does not call workflows,
    send HTTP or other external requests, execute tools, modify findings, or
    change target state. Missing or malformed error storage is initialized
    safely so callers can fail closed without crashing.
    """
    if not isinstance(result, dict):
        result = build_workflow_result()

    if not isinstance(result.get("errors"), list):
        result["errors"] = []

    result["errors"].append(dict(error) if isinstance(error, dict) else str(error))
    return result
