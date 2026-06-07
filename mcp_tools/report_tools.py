from tools.logger import log_event
from tools.report_writer import summarize_findings, write_report_draft


def register_report_tools(mcp) -> None:
    """
    Register reporting MCP wrappers.

    These wrappers delegate to the existing report writer utilities. They do
    not send external requests, call workflows, validate vulnerabilities,
    submit reports, or modify target state.
    """

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
