from mcp.server.fastmcp import FastMCP

from mcp_tools.report_tools import register_report_tools
from mcp_tools.risk_tools import register_risk_tools
from mcp_tools.scope_tools import register_scope_tools
from mcp_tools.workflow_tools import register_workflow_tools


mcp = FastMCP("Bug Bounty MCP Toolbox")

# Keep server.py as the MCP composition root only. Tool behavior lives in the
# grouped thin-wrapper modules; workflow logic, scope checks, risk evaluation,
# request budgets, and reporting behavior remain in their existing layers.
register_scope_tools(mcp)
register_risk_tools(mcp)
register_workflow_tools(mcp)
register_report_tools(mcp)


if __name__ == "__main__":
    mcp.run()
