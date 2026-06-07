from tools.logger import log_event
from tools.scope_guard import check_scope


def register_scope_tools(mcp) -> None:
    """
    Register scope-related MCP wrappers.

    The registered wrapper only calls the existing scope guard utility. It does
    not send external requests, call workflows, modify target state, or change
    risk policy. Keeping registration in this module makes server.py thinner
    while preserving the LM Studio tool name.
    """

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
