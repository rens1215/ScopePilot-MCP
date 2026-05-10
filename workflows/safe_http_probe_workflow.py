from tools.scope_guard import check_scope
from tools.http_probe import http_probe
from tools.storage import save_finding
from tools.logger import log_event

try:
    from tools.endpoint_classifier import classify_endpoint
except ImportError:
    classify_endpoint = None


def safe_http_probe_workflow(target: str) -> dict:
    """
    Safely perform one scoped HTTP probe workflow.

    Workflow:
    1. Check scope first.
    2. Stop if the target is out of scope.
    3. Perform exactly one low-risk HTTP probe if in scope.
    4. Optionally classify the endpoint if endpoint_classifier is available.
    5. Save the result as an observation.
    6. Return a concise summary.

    Safety:
    - No fuzzing.
    - No brute force.
    - No exploitation.
    - No crawling.
    - Exactly one HTTP probe request through http_probe().
    """

    log_event(f"tool called: tool_safe_http_probe_workflow target={target}")

    # 1. Scope check
    log_event(f"workflow: checking scope target={target}")
    scope = check_scope(target)

    log_event(
        f"workflow: scope result target={target} "
        f"in_scope={scope.get('in_scope')} "
        f"hostname={scope.get('hostname')} "
        f"scan_level={scope.get('allowed_scan_level')}"
    )

    if not scope.get("in_scope"):
        log_event(f"workflow: blocked out-of-scope target={target}")

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
                "crawling": False
            }
        }

    # 2. HTTP probe
    log_event(f"workflow: starting http_probe target={target}")
    probe = http_probe(target)

    log_event(
        f"workflow: http_probe completed target={target} "
        f"blocked={probe.get('blocked')} "
        f"status={probe.get('status_code')} "
        f"final_url={probe.get('final_url')} "
        f"error={probe.get('error')}"
    )

    # 3. Defense-in-depth: http_probe also has scope guard
    if probe.get("blocked"):
        log_event(f"workflow: http_probe blocked by scope guard target={target}")

        return {
            "target": target,
            "stopped": True,
            "reason": "HTTP probe was blocked by scope guard.",
            "scope": probe.get("scope"),
            "safety": {
                "requests_sent": 0,
                "scan_level": "blocked",
                "fuzzing": False,
                "bruteforce": False,
                "exploitation": False,
                "crawling": False
            }
        }

    # 4. Handle HTTP probe error
    if "error" in probe:
        log_event(
            f"workflow: http_probe error target={target} "
            f"error={probe.get('error')}"
        )

        finding = {
            "type": "observation",
            "title": "HTTP probe failed",
            "target": target,
            "category": "http_probe",
            "endpoint_classification": {
                "classification": "unknown",
                "confidence": "low",
                "reason": "HTTP probe failed before classification."
            },
            "severity": "info",
            "confidence": "low",
            "status": "needs_manual_validation",
            "evidence_summary": probe.get("error"),
            "next_step": "Manually verify whether the target is reachable."
        }

        log_event(f"workflow: saving error observation target={target}")
        saved = save_finding(finding)

        log_event(
            f"workflow: error observation saved target={target} "
            f"saved={saved.get('saved')} path={saved.get('path')}"
        )

        return {
            "target": target,
            "status": "error",
            "probe_error": probe.get("error"),
            "saved_observation": saved,
            "safety": {
                "requests_sent": 1,
                "scan_level": "low-risk",
                "fuzzing": False,
                "bruteforce": False,
                "exploitation": False,
                "crawling": False
            }
        }

    # 5. Endpoint classification
    if classify_endpoint is not None:
        try:
            log_event(f"workflow: starting endpoint classification target={target}")
            classification = classify_endpoint(probe)

            log_event(
                f"workflow: endpoint classified target={target} "
                f"classification={classification.get('classification')} "
                f"confidence={classification.get('confidence')}"
            )
        except Exception as e:
            classification = {
                "classification": "unknown",
                "confidence": "low",
                "reason": f"classifier_error: {str(e)}"
            }

            log_event(
                f"workflow: endpoint classification error target={target} "
                f"error={str(e)}"
            )
    else:
        classification = {
            "classification": "unknown",
            "confidence": "low",
            "reason": "endpoint_classifier is not available."
        }

        log_event(
            f"workflow: endpoint classifier unavailable target={target}"
        )

    # 6. Save observation
    finding = {
        "type": "observation",
        "title": "HTTP probe result",
        "target": target,
        "category": "http_probe",
        "endpoint_classification": classification,
        "severity": "info",
        "confidence": "high",
        "status": "observation",
        "evidence_summary": (
            f"HTTP GET returned {probe.get('status_code')}. "
            f"Final URL: {probe.get('final_url')}. "
            f"Title: {probe.get('title')}. "
            f"Content-Type: {probe.get('content_type')}. "
            f"Body size: {probe.get('body_size')} bytes. "
            f"Endpoint classification: {classification.get('classification')} "
            f"({classification.get('confidence')})."
        ),
        "next_step": "Review the target manually or run a specific low-risk validator if needed."
    }

    log_event(f"workflow: saving observation target={target}")
    saved = save_finding(finding)

    log_event(
        f"workflow: observation saved target={target} "
        f"saved={saved.get('saved')} path={saved.get('path')}"
    )

    # 7. Return result
    result = {
        "target": target,
        "scope": scope,
        "endpoint_classification": classification,
        "probe_summary": {
            "status_code": probe.get("status_code"),
            "final_url": probe.get("final_url"),
            "redirect_history": probe.get("redirect_history"),
            "title": probe.get("title"),
            "content_type": probe.get("content_type"),
            "body_size": probe.get("body_size")
        },
        "saved_observation": saved,
        "safety": {
            "requests_sent": 1,
            "scan_level": "low-risk",
            "fuzzing": False,
            "bruteforce": False,
            "exploitation": False,
            "crawling": False
        }
    }

    log_event(
        f"workflow: completed tool_safe_http_probe_workflow "
        f"target={target} requests_sent=1 "
        f"classification={classification.get('classification')}"
    )

    return result