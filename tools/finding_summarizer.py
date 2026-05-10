from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from tools.storage import load_findings
from tools.logger import log_event

try:
    from tools.priority_scorer import score_finding_priority
except ImportError:
    score_finding_priority = None


def _safe_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _safe_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _get_finding(record: dict) -> dict:
    """
    storage.py stores records as:
    {
        "timestamp": "...",
        "finding": {...}
    }
    """
    if not isinstance(record, dict):
        return {}

    finding = record.get("finding", {})
    return finding if isinstance(finding, dict) else {}


def _get_timestamp(record: dict) -> str:
    if not isinstance(record, dict):
        return ""
    return record.get("timestamp", "")


def _parse_timestamp(ts: str) -> datetime:
    """
    Best-effort timestamp parser.
    If parsing fails, return datetime.min so newer valid records win.
    """
    if not ts:
        return datetime.min

    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return datetime.min


def _normalize_target(target: str | None) -> str:
    if not target:
        return "unknown"

    target = str(target).strip()

    if target.endswith("/"):
        target = target[:-1]

    return target.lower()


def _dedupe_key(record: dict) -> tuple:
    finding = _get_finding(record)

    target = _normalize_target(finding.get("target"))
    category = finding.get("category") or finding.get("vulnerability_category") or "unknown"
    title = finding.get("title") or "untitled"
    status = finding.get("status") or finding.get("type") or "unknown"

    return (
        target,
        str(category).lower(),
        str(title).lower(),
        str(status).lower()
    )


def _deduplicate_latest(records: list[dict]) -> list[dict]:
    """
    Deduplicate by target + category + title + status.
    Keep the newest record.
    """
    latest_by_key = {}

    for record in records:
        key = _dedupe_key(record)
        current_ts = _parse_timestamp(_get_timestamp(record))

        if key not in latest_by_key:
            latest_by_key[key] = record
            continue

        existing_ts = _parse_timestamp(_get_timestamp(latest_by_key[key]))

        if current_ts >= existing_ts:
            latest_by_key[key] = record

    return list(latest_by_key.values())


def _extract_endpoint_classification(finding: dict) -> dict:
    classification = finding.get("endpoint_classification")

    if isinstance(classification, dict):
        return classification

    return {
        "classification": "unknown",
        "confidence": "low",
        "reason": "No endpoint classification found."
    }


def _extract_validator_result(finding: dict) -> dict:
    validator = finding.get("validator_result")

    if isinstance(validator, dict):
        return validator

    return {}


def _extract_priority_from_finding(finding: dict) -> dict:
    """
    Use existing priority if present.
    Otherwise calculate priority using priority_scorer.py when available.
    """

    # passive_recon summary may already contain priority inside summary
    summary = _safe_dict(finding.get("summary"))
    priority = _safe_dict(summary.get("priority"))

    if priority:
        return {
            "priority": priority.get("priority", "low"),
            "score": priority.get("score", 0),
            "reasons": priority.get("reasons", [])
        }

    # direct priority field
    direct_priority = finding.get("priority")
    if isinstance(direct_priority, dict):
        return {
            "priority": direct_priority.get("priority", "low"),
            "score": direct_priority.get("score", 0),
            "reasons": direct_priority.get("reasons", [])
        }

    validator = _extract_validator_result(finding)

    finding_type = finding.get("type", "observation")
    vulnerability_category = (
        finding.get("vulnerability_category")
        or finding.get("category")
        or "unknown"
    )
    endpoint_classification = _extract_endpoint_classification(finding)

    severity = (
        finding.get("severity")
        or validator.get("severity")
        or "info"
    )
    confidence = (
        finding.get("confidence")
        or validator.get("confidence")
        or "medium"
    )
    status = (
        finding.get("status")
        or validator.get("status")
        or finding_type
        or "observation"
    )
    should_report = bool(validator.get("should_report", False))

    if score_finding_priority is not None:
        try:
            return score_finding_priority(
                finding_type=finding_type,
                vulnerability_category=vulnerability_category,
                endpoint_classification=endpoint_classification,
                severity=severity,
                confidence=confidence,
                status=status,
                should_report=should_report
            )
        except Exception as e:
            log_event(f"finding_summarizer: priority scoring error={str(e)}")

    # fallback simple priority
    if finding_type == "confirmed_finding":
        return {
            "priority": "high",
            "score": 90,
            "reasons": ["Confirmed finding."]
        }

    if finding_type == "candidate_finding" or status == "candidate_finding":
        return {
            "priority": "medium",
            "score": 50,
            "reasons": ["Candidate finding requires manual validation."]
        }

    return {
        "priority": "low",
        "score": 10,
        "reasons": ["Observation only."]
    }


def _priority_sort_value(priority: dict) -> int:
    return int(priority.get("score", 0))


def _make_item(record: dict) -> dict:
    finding = _get_finding(record)
    validator = _extract_validator_result(finding)
    endpoint_classification = _extract_endpoint_classification(finding)
    priority = _extract_priority_from_finding(finding)

    category = (
        finding.get("category")
        or finding.get("vulnerability_category")
        or "unknown"
    )

    status = (
        finding.get("status")
        or validator.get("status")
        or finding.get("type")
        or "unknown"
    )

    severity = (
        finding.get("severity")
        or validator.get("severity")
        or "info"
    )

    confidence = (
        finding.get("confidence")
        or validator.get("confidence")
        or "medium"
    )

    return {
        "timestamp": _get_timestamp(record),
        "target": finding.get("target", "unknown"),
        "title": finding.get("title", "Untitled finding"),
        "type": finding.get("type", "unknown"),
        "category": category,
        "vulnerability_category": finding.get("vulnerability_category", category),
        "status": status,
        "severity": severity,
        "confidence": confidence,
        "endpoint_classification": endpoint_classification,
        "priority": priority,
        "should_report": bool(validator.get("should_report", False)),
        "evidence_summary": finding.get("evidence_summary", ""),
        "next_step": finding.get("next_step", ""),
        "validator_reason": validator.get("reason"),
        "false_positive_notes": validator.get("false_positive_notes", [])
    }


def _generate_recommended_next_steps(items: list[dict]) -> list[str]:
    steps = []

    categories = Counter(item.get("category", "unknown") for item in items)
    statuses = Counter(item.get("status", "unknown") for item in items)

    has_frontend = any(
        _safe_dict(item.get("endpoint_classification")).get("classification") == "frontend"
        for item in items
    )

    has_api = any(
        _safe_dict(item.get("endpoint_classification")).get("classification") == "api"
        for item in items
    )

    security_candidates = [
        item for item in items
        if item.get("category") == "security_header"
        and item.get("status") == "candidate_finding"
    ]

    cors_candidates = [
        item for item in items
        if item.get("category") == "cors"
        and item.get("status") == "candidate_finding"
    ]

    if security_candidates:
        steps.append(
            f"Review {len(security_candidates)} security header candidate finding(s) manually. "
            "Missing headers alone are often not reportable unless practical impact is shown."
        )

    if cors_candidates:
        steps.append(
            f"Review {len(cors_candidates)} CORS candidate finding(s) manually with an authorized test account "
            "and a non-destructive endpoint only if the program policy allows it."
        )

    if has_frontend:
        steps.append(
            "Consider adding a safe JS endpoint extraction workflow for frontend targets."
        )

    if has_api:
        steps.append(
            "For API targets, prioritize manual review of authentication, authorization, CORS, and response sensitivity."
        )

    if statuses.get("confirmed_finding", 0) > 0:
        steps.append(
            "Confirmed findings should be reviewed carefully, verified against scope and policy, then drafted into reports."
        )

    if not steps:
        if categories:
            steps.append(
                "No high-priority candidate found. Continue with low-risk recon or manually review observations."
            )
        else:
            steps.append(
                "No findings available yet. Run a safe workflow first."
            )

    return steps


def summarize_findings_advanced(limit: int = 100, dedupe: bool = True, top_n: int = 10) -> dict:
    """
    Advanced finding summarizer.

    Features:
    - load records from findings.jsonl
    - deduplicate repeated findings
    - group by target/category/status/severity
    - score and sort priorities
    - generate next-step recommendations
    """

    log_event(
        f"tool called: summarize_findings_advanced "
        f"limit={limit} dedupe={dedupe} top_n={top_n}"
    )

    records = load_findings(limit=limit)

    total_records = len(records)

    if dedupe:
        working_records = _deduplicate_latest(records)
    else:
        working_records = records

    items = [_make_item(record) for record in working_records]

    targets = sorted({
        _normalize_target(item.get("target"))
        for item in items
        if item.get("target")
    })

    by_type = Counter(item.get("type", "unknown") for item in items)
    by_category = Counter(item.get("category", "unknown") for item in items)
    by_status = Counter(item.get("status", "unknown") for item in items)
    by_severity = Counter(item.get("severity", "unknown") for item in items)

    by_endpoint_classification = Counter(
        _safe_dict(item.get("endpoint_classification")).get("classification", "unknown")
        for item in items
    )

    confirmed_findings = [
        item for item in items
        if item.get("type") == "confirmed_finding"
        or item.get("status") == "confirmed_finding"
    ]

    candidate_findings = [
        item for item in items
        if item.get("type") == "candidate_finding"
        or item.get("status") == "candidate_finding"
    ]

    observations = [
        item for item in items
        if item not in confirmed_findings
        and item not in candidate_findings
        and item.get("type") == "observation"
    ]

    needs_manual_validation = [
        item for item in items
        if item.get("status") == "needs_manual_validation"
    ]

    sorted_by_priority = sorted(
        items,
        key=lambda item: _priority_sort_value(_safe_dict(item.get("priority"))),
        reverse=True
    )

    top_priorities = sorted_by_priority[:top_n]

    recommended_next_steps = _generate_recommended_next_steps(items)

    summary = {
        "total_records": total_records,
        "unique_items": len(items),
        "dedupe_enabled": dedupe,
        "targets": targets,
        "counts": {
            "confirmed_findings": len(confirmed_findings),
            "candidate_findings": len(candidate_findings),
            "observations": len(observations),
            "needs_manual_validation": len(needs_manual_validation)
        },
        "by_type": dict(by_type),
        "by_category": dict(by_category),
        "by_status": dict(by_status),
        "by_severity": dict(by_severity),
        "by_endpoint_classification": dict(by_endpoint_classification),
        "top_priorities": [
            {
                "target": item.get("target"),
                "title": item.get("title"),
                "category": item.get("category"),
                "vulnerability_category": item.get("vulnerability_category"),
                "status": item.get("status"),
                "severity": item.get("severity"),
                "confidence": item.get("confidence"),
                "endpoint_classification": item.get("endpoint_classification"),
                "priority": item.get("priority"),
                "should_report": item.get("should_report"),
                "evidence_summary": item.get("evidence_summary"),
                "next_step": item.get("next_step"),
                "validator_reason": item.get("validator_reason"),
                "false_positive_notes": item.get("false_positive_notes")
            }
            for item in top_priorities
        ],
        "candidate_findings": candidate_findings,
        "confirmed_findings": confirmed_findings,
        "needs_manual_validation": needs_manual_validation,
        "recommended_next_steps": recommended_next_steps
    }

    log_event(
        f"tool result: summarize_findings_advanced "
        f"total_records={total_records} unique_items={len(items)} "
        f"candidate_findings={len(candidate_findings)}"
    )

    return summary