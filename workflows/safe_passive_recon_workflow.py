from tools.scope_guard import check_scope
from tools.storage import save_finding
from tools.logger import log_event
from tools.priority_scorer import score_workflow_priority

from workflows.safe_http_probe_workflow import safe_http_probe_workflow
from workflows.safe_security_headers_workflow import safe_security_headers_workflow
from workflows.safe_cors_observation_workflow import safe_cors_observation_workflow


def _extract_status(result: dict) -> str:
    if result.get("stopped"):
        return "stopped"
    if result.get("status") == "error":
        return "error"
    return "completed"


def _extract_candidate_count(results: list[dict]) -> int:
    count = 0

    for result in results:
        validator = result.get("validator_result", {})
        if validator.get("status") == "candidate_finding":
            count += 1

    return count


def _extract_observation_count(results: list[dict]) -> int:
    count = 0

    for result in results:
        if result.get("stopped"):
            continue

        validator = result.get("validator_result")

        if validator is None:
            count += 1
            continue

        if validator.get("status") in ["observation", "needs_manual_validation"]:
            count += 1

    return count


def _get_endpoint_classification(*results: dict) -> dict:
    for result in results:
        classification = result.get("endpoint_classification")
        if isinstance(classification, dict):
            return classification

    return {
        "classification": "unknown",
        "confidence": "low",
        "reason": "No endpoint classification found in workflow results."
    }

'''
# initial edition of priority calculation logic - now moved to tools/priority_scorer.py
def _calculate_priority(
    endpoint_classification: dict,
    candidate_count: int,
    security_result: dict,
    cors_result: dict
) -> dict:
    """
    Conservative priority scorer.
    This is not severity. It only tells the user which result deserves manual review first.
    """

    classification = endpoint_classification.get("classification", "unknown")

    score = 0
    reasons = []

    if classification in ["admin_panel", "auth_service"]:
        score += 30
        reasons.append(f"High-value endpoint classification: {classification}")

    elif classification == "api":
        score += 25
        reasons.append("API endpoint classification may be more relevant for auth/CORS/access-control review.")

    elif classification == "frontend":
        score += 10
        reasons.append("Frontend endpoint may be relevant for client-side hardening observations.")

    if candidate_count > 0:
        score += 30
        reasons.append(f"{candidate_count} candidate finding(s) detected.")

    security_validator = security_result.get("validator_result", {})
    if security_validator.get("status") == "candidate_finding":
        score += 10
        reasons.append("Security headers validator produced a candidate finding.")

    cors_validator = cors_result.get("validator_result", {})
    if cors_validator.get("status") == "candidate_finding":
        score += 20
        reasons.append("CORS validator produced a candidate finding.")

    if score >= 70:
        priority = "high"
    elif score >= 40:
        priority = "medium"
    else:
        priority = "low"

    if not reasons:
        reasons.append("Only low-risk observations were detected.")

    return {
        "priority": priority,
        "score": score,
        "reasons": reasons
    }
'''

def safe_passive_recon_workflow(target: str) -> dict:
    """
    Safely perform a passive / low-risk recon workflow.

    Workflow:
    1. Check scope first.
    2. Stop if the target is out of scope.
    3. Run safe_http_probe_workflow.
    4. Run safe_security_headers_workflow.
    5. Run safe_cors_observation_workflow.
    6. Consolidate results.
    7. Save a summary observation.
    8. Return a concise passive recon summary.

    Safety:
    - No fuzzing.
    - No brute force.
    - No exploitation.
    - No crawling.
    - No credentialed requests.
    - No payload injection.
    - Expected total requests: 3
      1 from HTTP probe
      1 from security headers check
      1 from CORS observation
    """

    log_event(f"tool called: tool_safe_passive_recon_workflow target={target}")

    log_event(f"workflow: passive_recon checking scope target={target}")
    scope = check_scope(target)

    log_event(
        f"workflow: passive_recon scope result target={target} "
        f"in_scope={scope.get('in_scope')} "
        f"hostname={scope.get('hostname')} "
        f"scan_level={scope.get('allowed_scan_level')}"
    )

    if not scope.get("in_scope"):
        log_event(f"workflow: passive_recon blocked out-of-scope target={target}")

        return {
            "target": target,
            "stopped": True,
            "reason": "Target is not in scope.",
            "scope": scope,
            "safety": {
                "requests_sent": 0,
                "scan_level": "blocked",
                "fuzzing": False,
                "bruteforce": False,
                "exploitation": False,
                "crawling": False,
                "credentialed_request": False
            }
        }

    # 1. Safe HTTP probe
    log_event(f"workflow: passive_recon starting safe_http_probe_workflow target={target}")
    http_result = safe_http_probe_workflow(target)
    log_event(
        f"workflow: passive_recon safe_http_probe_workflow completed "
        f"target={target} status={_extract_status(http_result)}"
    )

    # 2. Safe security headers
    log_event(f"workflow: passive_recon starting safe_security_headers_workflow target={target}")
    security_result = safe_security_headers_workflow(target)
    log_event(
        f"workflow: passive_recon safe_security_headers_workflow completed "
        f"target={target} status={_extract_status(security_result)}"
    )

    # 3. Safe CORS observation
    log_event(f"workflow: passive_recon starting safe_cors_observation_workflow target={target}")
    cors_result = safe_cors_observation_workflow(target)
    log_event(
        f"workflow: passive_recon safe_cors_observation_workflow completed "
        f"target={target} status={_extract_status(cors_result)}"
    )

    workflow_results = [
        http_result,
        security_result,
        cors_result
    ]

    endpoint_classification = _get_endpoint_classification(
        http_result,
        security_result,
        cors_result
    )

    candidate_count = _extract_candidate_count(workflow_results)
    observation_count = _extract_observation_count(workflow_results)

    priority = score_workflow_priority(
        endpoint_classification=endpoint_classification,
        http_result=http_result,
        security_result=security_result,
        cors_result=cors_result
    )

    http_summary = http_result.get("probe_summary", {})
    security_summary = security_result.get("header_summary", {})
    cors_summary = cors_result.get("cors_summary", {})

    recommended_next_steps = []

    if security_result.get("validator_result", {}).get("status") == "candidate_finding":
        recommended_next_steps.append(
            "Manually review whether missing security headers create practical impact before reporting."
        )

    if cors_result.get("validator_result", {}).get("status") == "candidate_finding":
        recommended_next_steps.append(
            "Manually validate CORS behavior with an authorized test account and non-destructive endpoint only if policy allows."
        )

    if endpoint_classification.get("classification") == "frontend":
        recommended_next_steps.append(
            "Consider running a future safe JS endpoint extraction workflow on directly referenced frontend scripts."
        )

    if endpoint_classification.get("classification") == "api":
        recommended_next_steps.append(
            "Prioritize manual review of authentication, authorization, CORS, and response sensitivity."
        )

    if not recommended_next_steps:
        recommended_next_steps.append(
            "No high-priority issue detected. Review observations manually and continue with other low-risk recon workflows if needed."
        )

    consolidated_finding = {
        "type": "observation",
        "title": "Passive recon summary",
        "target": target,
        "category": "passive_recon",
        "vulnerability_category": "recon_summary",
        "endpoint_classification": endpoint_classification,
        "severity": "info",
        "confidence": "high",
        "status": "observation",
        "summary": {
            "http_probe": {
                "status_code": http_summary.get("status_code"),
                "final_url": http_summary.get("final_url"),
                "title": http_summary.get("title"),
                "content_type": http_summary.get("content_type"),
                "body_size": http_summary.get("body_size")
            },
            "security_headers": {
                "missing_headers": security_summary.get("missing_headers"),
                "missing_count": security_summary.get("missing_count"),
                "validator_result": security_result.get("validator_result")
            },
            "cors": {
                "origin_tested": cors_summary.get("origin_tested"),
                "origin_reflected": cors_summary.get("origin_reflected"),
                "cors_headers": cors_summary.get("cors_headers"),
                "validator_result": cors_result.get("validator_result")
            },
            "candidate_count": candidate_count,
            "observation_count": observation_count,
            "priority": priority
        },
        "evidence_summary": (
            f"Passive recon completed for {target}. "
            f"Endpoint classification: {endpoint_classification.get('classification')} "
            f"({endpoint_classification.get('confidence')}). "
            f"Candidate findings: {candidate_count}. "
            f"Observations: {observation_count}. "
            f"Priority: {priority.get('priority')}."
        ),
        "next_step": " ".join(recommended_next_steps)
    }

    log_event(f"workflow: passive_recon saving consolidated summary target={target}")
    saved = save_finding(consolidated_finding)

    log_event(
        f"workflow: passive_recon consolidated summary saved target={target} "
        f"saved={saved.get('saved')} path={saved.get('path')}"
    )

    result = {
        "target": target,
        "scope": scope,
        "endpoint_classification": endpoint_classification,
        "workflow_status": {
            "http_probe": _extract_status(http_result),
            "security_headers": _extract_status(security_result),
            "cors_observation": _extract_status(cors_result)
        },
        "summary": {
            "http_probe": http_summary,
            "security_headers": security_summary,
            "cors": cors_summary,
            "candidate_count": candidate_count,
            "observation_count": observation_count,
            "priority": priority,
            "recommended_next_steps": recommended_next_steps
        },
        "saved_summary": saved,
        "safety": {
            "requests_sent": 3,
            "scan_level": "low-risk",
            "fuzzing": False,
            "bruteforce": False,
            "exploitation": False,
            "crawling": False,
            "credentialed_request": False
        }
    }

    log_event(
        f"workflow: completed tool_safe_passive_recon_workflow "
        f"target={target} requests_sent=3 "
        f"candidate_count={candidate_count} "
        f"priority={priority.get('priority')}"
    )

    return result