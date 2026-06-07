# MCP Server for LLM Hacker

Current stable version:

```text
v0.5-core-refactor-and-result-standardization
```

This project is an AI-assisted authorized web security testing platform built around MCP tools. It is intended for explicitly authorized, in-scope reconnaissance, attack surface inventory, evidence organization, finding summarization, and report draft generation.

It is not an unrestricted attack automation tool and does not claim to automatically exploit or compromise targets.

## Current MCP Tools

```text
tool_check_scope
tool_evaluate_action_risk
tool_safe_http_probe_workflow
tool_safe_security_headers_workflow
tool_safe_cors_observation_workflow
tool_safe_passive_recon_workflow
tool_safe_robots_securitytxt_workflow
tool_safe_sitemap_parser_workflow
tool_safe_js_endpoint_extraction_workflow
tool_safe_bounded_crawl_workflow
tool_summarize_findings
tool_write_report_draft
```

## v0.5 Refactor

v0.5 completed result and wrapper standardization:

* Shared safety metadata helper
* Shared workflow result schema helper
* Shared HTTP result utility helper
* Shared inventory candidate builder
* Refactored safe workflows to use shared helpers
* Split MCP wrappers into `mcp_tools/`
* Added MCP tool registration tests

`server.py` is now the MCP composition root. MCP wrappers are grouped under:

```text
mcp_tools/scope_tools.py
mcp_tools/risk_tools.py
mcp_tools/workflow_tools.py
mcp_tools/report_tools.py
```

## Safety Boundary

v0.5 did not add exploit automation, fuzzing, brute force, credential testing, form submission, state-changing actions, destructive actions, new external request behavior, new request budgets, or new vulnerability validation.

Future controlled validation belongs to `v0.6-controlled-validation` and must still use scope guard, risk gate, explicit approval, request limits, evidence rules, and sensitive-data minimization.
