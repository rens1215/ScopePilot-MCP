import json

from mcp.server.fastmcp import FastMCP

from tools.scope_guard import check_scope
from tools.dns_lookup import dns_lookup
from tools.http_probe import http_probe
from tools.security_headers import security_headers_check
from tools.storage import save_finding
from tools.report_writer import summarize_findings, write_report_draft
from tools.logger import log_event

from workflows.safe_http_probe_workflow import safe_http_probe_workflow
from workflows.safe_security_headers_workflow import safe_security_headers_workflow
from workflows.safe_cors_observation_workflow import safe_cors_observation_workflow
from workflows.safe_passive_recon_workflow import safe_passive_recon_workflow


mcp = FastMCP("Bug Bounty MCP Toolbox")


@mcp.tool()
def tool_check_scope(target: str) -> dict:
    """
    Check whether a target URL or hostname is allowed by the local bug bounty scope configuration.
    Always call this before using any other scanning or probing tool.
    """
    log_event(f"tool called: tool_check_scope target={target}")

    result = check_scope(target)

    log_event(
        f"tool result: tool_check_scope target={target} "
        f"in_scope={result.get('in_scope')} hostname={result.get('hostname')}"
    )

    return result


#@mcp.tool()
def tool_dns_lookup(target: str) -> dict:
    """
    Perform a low-risk DNS lookup for an in-scope target.
    Returns A, AAAA, CNAME, MX, and TXT records when available.
    """
    log_event(f"tool called: tool_dns_lookup target={target}")

    result = dns_lookup(target)

    log_event(
        f"tool result: tool_dns_lookup target={target} "
        f"blocked={result.get('blocked')}"
    )

    return result


#@mcp.tool()
def tool_http_probe(target: str) -> dict:
    """
    Perform a single low-risk HTTP GET request against an in-scope target.
    Returns status code, final URL, redirect chain, selected headers, title, and body size.
    """
    log_event(f"tool called: tool_http_probe target={target}")

    result = http_probe(target)

    log_event(
        f"tool result: tool_http_probe target={target} "
        f"blocked={result.get('blocked')} status={result.get('status_code')} "
        f"error={result.get('error')}"
    )

    return result


#@mcp.tool()
def tool_security_headers_check(target: str) -> dict:
    """
    Check common security headers on an in-scope HTTP target.
    Missing headers should usually be treated as informational or low severity unless concrete impact is proven.
    """
    log_event(f"tool called: tool_security_headers_check target={target}")

    result = security_headers_check(target)

    log_event(
        f"tool result: tool_security_headers_check target={target} "
        f"blocked={result.get('blocked')} severity={result.get('severity')} "
        f"missing_count={len(result.get('missing', [])) if isinstance(result.get('missing'), list) else 0}"
    )

    return result


@mcp.tool()
def tool_safe_http_probe_workflow(target: str) -> dict:
    """
    Safely perform one scoped HTTP probe workflow.

    This tool will:
    1. Check scope first.
    2. Stop if the target is out of scope.
    3. Perform exactly one low-risk HTTP probe if in scope.
    4. Classify the endpoint if endpoint_classifier is available.
    5. Save the result as an observation.
    6. Return a concise summary.

    This tool does not fuzz, brute force, crawl, exploit, or perform high-volume scanning.
    """
    return safe_http_probe_workflow(target)


@mcp.tool()
def tool_safe_security_headers_workflow(target: str) -> dict:
    """
    Safely perform one scoped security headers workflow.

    This tool will:
    1. Check scope first.
    2. Stop if the target is out of scope.
    3. Perform one low-risk security headers check if in scope.
    4. Classify the endpoint if endpoint_classifier is available.
    5. Validate missing headers conservatively.
    6. Save the result as an observation or candidate_finding.
    7. Return a concise summary.

    This tool does not fuzz, brute force, crawl, exploit, or perform high-volume scanning.
    """
    return safe_security_headers_workflow(target)


@mcp.tool()
def tool_safe_cors_observation_workflow(
    target: str,
    test_origin: str = "https://example-attacker.invalid"
) -> dict:
    """
    Safely perform one scoped CORS observation workflow.

    This tool will:
    1. Check scope first.
    2. Stop if the target is out of scope.
    3. Send exactly one low-risk GET request with a harmless Origin header.
    4. Observe CORS response headers.
    5. Classify the endpoint if endpoint_classifier is available.
    6. Validate CORS behavior conservatively.
    7. Save the result as an observation or candidate_finding.
    8. Return a concise summary.

    This tool does not fuzz, brute force, crawl, exploit, or perform high-volume scanning.
    It does not send cookies, tokens, credentials, or sensitive data.
    """
    return safe_cors_observation_workflow(
        target=target,
        test_origin=test_origin
    )


@mcp.tool()
def tool_safe_passive_recon_workflow(target: str) -> dict:
    """
    Safely perform a passive / low-risk recon workflow.

    This tool will:
    1. Check scope first.
    2. Stop if the target is out of scope.
    3. Run safe HTTP probe.
    4. Run safe security headers workflow.
    5. Run safe CORS observation workflow.
    6. Consolidate results.
    7. Save a passive recon summary.
    8. Return prioritized next steps.

    This tool does not fuzz, brute force, crawl, exploit, or perform high-volume scanning.
    Expected total requests: 3.
    """
    return safe_passive_recon_workflow(target)


#@mcp.tool()
def tool_save_finding(finding_json: str) -> dict:
    """
    Save a finding, candidate finding, or observation to the local findings.jsonl file.

    The input must be a JSON string.
    Do not save secrets, cookies, tokens, personal data, or sensitive response bodies.
    """
    log_event(
        f"tool called: tool_save_finding "
        f"input_length={len(finding_json) if finding_json is not None else 0}"
    )

    try:
        finding = json.loads(finding_json)
    except json.JSONDecodeError as e:
        log_event(f"tool error: tool_save_finding invalid_json error={str(e)}")

        return {
            "saved": False,
            "error": "Invalid JSON string.",
            "details": str(e),
            "received": finding_json
        }

    saved = save_finding(finding)

    log_event(
        f"tool result: tool_save_finding saved={saved.get('saved')} "
        f"type={finding.get('type')} target={finding.get('target')}"
    )

    return saved


#@mcp.tool()
def tool_save_observation(
    title: str,
    target: str,
    category: str,
    severity: str,
    confidence: str,
    status: str,
    evidence_summary: str,
    next_step: str
) -> dict:
    """
    Save a simple observation using flat string parameters.
    This is easier for local LLMs than passing a nested JSON object.
    """
    log_event(
        f"tool called: tool_save_observation "
        f"title={title} target={target} category={category} severity={severity}"
    )

    finding = {
        "type": "observation",
        "title": title,
        "target": target,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "status": status,
        "evidence_summary": evidence_summary,
        "next_step": next_step
    }

    saved = save_finding(finding)

    log_event(
        f"tool result: tool_save_observation saved={saved.get('saved')} "
        f"target={target} path={saved.get('path')}"
    )

    return saved


@mcp.tool()
def tool_summarize_findings(limit: int = 50) -> dict:
    """
    Summarize locally saved findings, candidate findings, and observations.
    """
    log_event(f"tool called: tool_summarize_findings limit={limit}")

    result = summarize_findings(limit)

    log_event(
        f"tool result: tool_summarize_findings "
        f"total_records={result.get('total_records')}"
    )

    return result


@mcp.tool()
def tool_write_report_draft(
    title: str,
    target: str,
    vulnerability_type: str,
    severity: str,
    evidence: str,
    impact: str,
    steps_to_reproduce: list[str],
    recommendation: str
) -> str:
    """
    Generate a bug bounty report draft from validated evidence.
    This tool does not submit the report.
    """
    log_event(
        f"tool called: tool_write_report_draft "
        f"title={title} target={target} severity={severity} "
        f"vulnerability_type={vulnerability_type}"
    )

    report = write_report_draft(
        title=title,
        target=target,
        vulnerability_type=vulnerability_type,
        severity=severity,
        evidence=evidence,
        impact=impact,
        steps_to_reproduce=steps_to_reproduce,
        recommendation=recommendation
    )

    log_event(
        f"tool result: tool_write_report_draft "
        f"target={target} report_length={len(report)}"
    )

    return report


if __name__ == "__main__":
    mcp.run()