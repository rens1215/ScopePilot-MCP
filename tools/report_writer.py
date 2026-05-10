from tools.storage import load_findings
from tools.finding_summarizer import summarize_findings_advanced    


def summarize_findings(limit: int = 50) -> dict:
    """
    Summarize locally saved findings, candidate findings, and observations.

    This function now uses the advanced finding summarizer:
    - deduplication
    - priority ranking
    - grouping
    - recommended next steps
    """
    return summarize_findings_advanced(
        limit=limit,
        dedupe=True,
        top_n=10
    )


def write_report_draft(
    title: str,
    target: str,
    vulnerability_type: str,
    severity: str,
    evidence: str,
    impact: str,
    steps_to_reproduce: list[str],
    recommendation: str
) -> str:
    steps = "\n".join(
        [f"{idx + 1}. {step}" for idx, step in enumerate(steps_to_reproduce)]
    )

    return f"""# {title}

## Target

{target}

## Vulnerability Type

{vulnerability_type}

## Severity

{severity}

## Summary

A potential security issue was identified on the target. This draft requires manual validation before submission.

## Steps to Reproduce

{steps}

## Evidence

{evidence}

## Impact

{impact}

## Recommendation

{recommendation}

## Validation Status

Needs manual validation before submitting to the bug bounty platform.

## Safety Note

This report draft was generated from low-risk MCP tools. Do not submit unless the finding is reproducible, in-scope, and compliant with the program policy.
"""