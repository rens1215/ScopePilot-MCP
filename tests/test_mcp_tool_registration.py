import sys
from inspect import signature
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from mcp_tools.report_tools import register_report_tools
from mcp_tools.risk_tools import register_risk_tools
from mcp_tools.scope_tools import register_scope_tools
from mcp_tools.workflow_tools import register_workflow_tools


EXPECTED_TOOL_NAMES = {
    "tool_check_scope",
    "tool_evaluate_action_risk",
    "tool_safe_http_probe_workflow",
    "tool_safe_security_headers_workflow",
    "tool_safe_cors_observation_workflow",
    "tool_safe_passive_recon_workflow",
    "tool_safe_robots_securitytxt_workflow",
    "tool_safe_sitemap_parser_workflow",
    "tool_safe_js_endpoint_extraction_workflow",
    "tool_safe_bounded_crawl_workflow",
    "tool_summarize_findings",
    "tool_write_report_draft",
}


class FakeMCP:
    """
    Minimal MCP decorator recorder for registration tests.

    The fake records wrapper names only. It never executes registered tools,
    never calls workflows, never sends external requests, and never modifies
    target state.
    """

    def __init__(self):
        self.registered_tools = {}

    def tool(self):
        def decorator(function):
            self.registered_tools[function.__name__] = function
            return function

        return decorator


def assert_true(condition, message):
    """Assert MCP registration behavior without invoking any registered tool."""
    if not condition:
        raise AssertionError(message)


def test_expected_mcp_tool_names_are_registered():
    """Protects the LM Studio toolbox contract while keeping registration local."""
    fake_mcp = FakeMCP()

    register_scope_tools(fake_mcp)
    register_risk_tools(fake_mcp)
    register_workflow_tools(fake_mcp)
    register_report_tools(fake_mcp)

    registered_names = set(fake_mcp.registered_tools)

    assert_true(
        registered_names == EXPECTED_TOOL_NAMES,
        f"Expected {EXPECTED_TOOL_NAMES}, got {registered_names}",
    )


def test_registration_does_not_execute_registered_tools():
    """Protects against accidental workflow execution during MCP registration."""
    fake_mcp = FakeMCP()

    register_workflow_tools(fake_mcp)

    assert_true(
        set(fake_mcp.registered_tools) == {
            "tool_safe_http_probe_workflow",
            "tool_safe_security_headers_workflow",
            "tool_safe_cors_observation_workflow",
            "tool_safe_passive_recon_workflow",
            "tool_safe_robots_securitytxt_workflow",
            "tool_safe_sitemap_parser_workflow",
            "tool_safe_js_endpoint_extraction_workflow",
            "tool_safe_bounded_crawl_workflow",
        },
        "Workflow registration should record wrappers without executing them.",
    )


def test_registered_tool_signatures_are_stable():
    """Protects MCP wrapper call schemas after moving wrappers out of server.py."""
    fake_mcp = FakeMCP()

    register_scope_tools(fake_mcp)
    register_risk_tools(fake_mcp)
    register_workflow_tools(fake_mcp)
    register_report_tools(fake_mcp)

    expected_parameters = {
        "tool_check_scope": ["target"],
        "tool_evaluate_action_risk": ["tool_name", "target", "mode", "user_approved"],
        "tool_safe_http_probe_workflow": ["target"],
        "tool_safe_security_headers_workflow": ["target"],
        "tool_safe_cors_observation_workflow": ["target", "test_origin"],
        "tool_safe_passive_recon_workflow": ["target"],
        "tool_safe_robots_securitytxt_workflow": ["target"],
        "tool_safe_sitemap_parser_workflow": ["target", "max_sitemap_bytes", "max_urls"],
        "tool_safe_js_endpoint_extraction_workflow": ["target", "max_js_files", "max_js_bytes", "max_candidates"],
        "tool_safe_bounded_crawl_workflow": [
            "target",
            "max_pages",
            "max_depth",
            "max_requests",
            "rate_delay_seconds",
            "max_links_per_page",
        ],
        "tool_summarize_findings": ["limit"],
        "tool_write_report_draft": [
            "title",
            "target",
            "vulnerability_type",
            "severity",
            "evidence",
            "impact",
            "steps_to_reproduce",
            "recommendation",
        ],
    }

    for tool_name, parameter_names in expected_parameters.items():
        actual = list(signature(fake_mcp.registered_tools[tool_name]).parameters)
        assert_true(actual == parameter_names, f"{tool_name} parameters changed: {actual}")


if __name__ == "__main__":
    test_expected_mcp_tool_names_are_registered()
    test_registration_does_not_execute_registered_tools()
    test_registered_tool_signatures_are_stable()

    print("All MCP tool registration tests passed.")
