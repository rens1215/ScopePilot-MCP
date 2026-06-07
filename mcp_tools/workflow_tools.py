from workflows.safe_bounded_crawl_workflow import safe_bounded_crawl_workflow
from workflows.safe_cors_observation_workflow import safe_cors_observation_workflow
from workflows.safe_http_probe_workflow import safe_http_probe_workflow
from workflows.safe_js_endpoint_extraction_workflow import safe_js_endpoint_extraction_workflow
from workflows.safe_passive_recon_workflow import safe_passive_recon_workflow
from workflows.safe_robots_securitytxt_workflow import safe_robots_securitytxt_workflow
from workflows.safe_security_headers_workflow import safe_security_headers_workflow
from workflows.safe_sitemap_parser_workflow import safe_sitemap_parser_workflow


def register_workflow_tools(mcp) -> None:
    """
    Register workflow MCP wrappers.

    These wrappers are intentionally thin. They delegate scope checks, request
    handling, parsing, validation, inventory building, storage, and logging to
    the existing workflows. This module does not send HTTP requests directly,
    add request paths, change request budgets, or implement workflow logic.
    """

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

    @mcp.tool()
    def tool_safe_robots_securitytxt_workflow(target: str) -> dict:
        """
        Call the safe robots/security.txt/sitemap metadata workflow.

        This MCP wrapper stays thin and delegates all scope checks, request
        handling, metadata filtering, and inventory candidate building to the
        workflow. The risk profile is defined in config/tool_risk_profiles.json.

        Safety boundary:
        - Scope check is performed inside the workflow before any request.
        - The robots metadata workflow sends at most 3 requests.
        - This wrapper does not send HTTP requests directly.
        - This wrapper does not parse, validate, crawl, or build inventory itself.
        """
        return safe_robots_securitytxt_workflow(target)

    @mcp.tool()
    def tool_safe_sitemap_parser_workflow(
        target: str,
        max_sitemap_bytes: int = 1048576,
        max_urls: int = 100
    ) -> dict:
        """
        Call the safe sitemap parser workflow.

        This MCP wrapper stays thin and delegates all scope checks, request
        handling, sitemap parsing, URL normalization, validation, and inventory
        candidate building to the workflow. The risk profile is defined in
        config/tool_risk_profiles.json.

        Safety boundary:
        - Scope check is performed inside the workflow before any request.
        - The sitemap workflow sends at most 1 request, to /sitemap.xml.
        - The sitemap workflow does not request URLs listed inside the sitemap.
        - This wrapper does not send HTTP requests directly.
        - This wrapper does not parse, validate, crawl, or build inventory itself.
        """
        return safe_sitemap_parser_workflow(
            target=target,
            max_sitemap_bytes=max_sitemap_bytes,
            max_urls=max_urls
        )

    @mcp.tool()
    def tool_safe_js_endpoint_extraction_workflow(
        target: str,
        max_js_files: int = 20,
        max_js_bytes: int = 500000,
        max_candidates: int = 100
    ) -> dict:
        """
        Call the safe JavaScript endpoint extraction workflow.

        This MCP wrapper stays thin and delegates all scope checks, request
        handling, HTML parsing, JavaScript static parsing, endpoint validation, and
        inventory candidate building to safe_js_endpoint_extraction_workflow. The
        risk profile is defined in config/tool_risk_profiles.json.

        Safety boundary:
        - Scope check is performed inside the workflow before any request.
        - This tool is medium risk and requires explicit approval through policy.
        - Default budget is at most 20 JavaScript files.
        - Hard cap is at most 30 JavaScript files.
        - Total hard request cap is 31: one HTML request plus up to 30 JS requests.
        - It does not execute JavaScript or evaluate JavaScript.
        - It does not request API endpoints extracted from JavaScript.
        - It is not a crawler.
        - It does not fuzz, brute force, exploit, or use credentials.
        - This wrapper does not send HTTP requests directly or build inventory itself.
        """
        return safe_js_endpoint_extraction_workflow(
            target=target,
            max_js_files=max_js_files,
            max_js_bytes=max_js_bytes,
            max_candidates=max_candidates
        )

    @mcp.tool()
    def tool_safe_bounded_crawl_workflow(
        target: str,
        max_pages: int = 30,
        max_depth: int = 2,
        max_requests: int = 30,
        rate_delay_seconds: float = 0.5,
        max_links_per_page: int = 200
    ) -> dict:
        """
        Call the safe bounded in-scope crawl workflow.

        This MCP wrapper stays thin and delegates all scope checks, request
        handling, bounded crawling, HTML parsing, URL queue management, endpoint
        validation, and inventory candidate building to safe_bounded_crawl_workflow.
        The risk profile is defined in config/tool_risk_profiles.json.

        Safety boundary:
        - Scope check is performed inside the workflow before any request.
        - This tool is medium risk and requires explicit approval through policy.
        - Default max_pages is 30.
        - Default max_depth is 2.
        - Default max_requests is 30.
        - It is a bounded in-scope crawler, not unrestricted crawling.
        - It only builds attack surface inventory and does not validate vulnerabilities.
        - It does not submit forms.
        - It does not use credentials.
        - It does not fuzz, brute force, or exploit.
        - It does not download JavaScript; script src values become inventory candidates only.
        - JavaScript endpoint extraction is handled by tool_safe_js_endpoint_extraction_workflow.
        - This wrapper does not send HTTP requests directly or build inventory itself.
        """
        return safe_bounded_crawl_workflow(
            target=target,
            max_pages=max_pages,
            max_depth=max_depth,
            max_requests=max_requests,
            rate_delay_seconds=rate_delay_seconds,
            max_links_per_page=max_links_per_page
        )
