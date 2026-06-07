from agent.approval_controller import build_approval_request
from agent.risk_gate import evaluate_tool_action
from tools.logger import log_event


def register_risk_tools(mcp) -> None:
    """
    Register risk evaluation MCP wrappers.

    The registered wrapper performs pre-execution policy evaluation only. It
    does not execute the target tool, call workflows, send HTTP or other
    external requests, or modify target state.
    """

    @mcp.tool()
    def tool_evaluate_action_risk(
        tool_name: str,
        target: str | None = None,
        mode: str = "authorized",
        user_approved: bool = False
    ) -> dict:
        """
        Evaluate a tool action before execution and build an approval request.

        This MCP wrapper is intentionally thin: it does not execute the target
        tool, does not call workflows, and does not send HTTP or other external
        requests. It is only for pre-execution risk evaluation.
        """
        log_event(
            f"tool called: tool_evaluate_action_risk "
            f"tool_name={tool_name} target={target} mode={mode} "
            f"user_approved={user_approved}"
        )

        risk_evaluation = evaluate_tool_action(
            tool_name=tool_name,
            target=target,
            mode=mode,
            user_approved=user_approved
        )
        approval_request = build_approval_request(
            tool_name=tool_name,
            target=target,
            risk_evaluation=risk_evaluation
        )

        log_event(
            f"tool result: tool_evaluate_action_risk "
            f"tool_name={tool_name} allowed={risk_evaluation.get('allowed')} "
            f"requires_approval={risk_evaluation.get('requires_approval')} "
            f"risk_level={risk_evaluation.get('risk_level')}"
        )

        return {
            "risk_evaluation": risk_evaluation,
            "approval_request": approval_request
        }
