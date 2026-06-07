# Architecture

## Project Name

```text
MCP_SERVER_FOR_LLM_HACKER
```

## System Goal

本專案是以 MCP tools 為核心的 AI-assisted authorized web security testing 平台。

系統目的在於協助 runtime AI agent 在明確授權、明確 in-scope 的目標上進行 scoped reconnaissance、attack surface inventory、evidence organization、finding prioritization、finding summarization 與 report draft generation。

本專案不是 unrestricted attack automation tool。任何 external action 都必須遵守 scope guard、risk gate、approval policy、request limits、workflow safety rules 與 evidence rules。

---

## Current Stable Version

Current stable version:

```text
v0.5-core-refactor-and-result-standardization
```

v0.5 已完成，並且是 refactor / standardization milestone。它沒有新增漏洞驗證能力，也沒有新增攻擊自動化能力。

---

## Completed Through v0.5

目前已完成：

* MCP server integration with LM Studio
* Scope guard
* Policy loader
* Tool risk profiles
* Risk gate
* Approval controller
* Risk evaluation MCP tool
* Runtime skill loader
* Runtime agent skill definitions
* Attack surface inventory foundation
* URL normalizer
* Endpoint inventory builder
* Inventory validator
* JavaScript endpoint extractor
* HTML link extractor
* Crawl queue
* Safe HTTP probe workflow
* Safe security headers workflow
* Safe CORS observation workflow
* Safe passive recon workflow
* Safe robots/security.txt/sitemap metadata workflow
* Safe sitemap parser workflow
* Safe JavaScript endpoint extraction workflow
* Safe bounded in-scope crawl workflow
* Finding summarizer
* Report draft writer
* Shared safety metadata helper: `tools/safety_metadata.py`
* Shared result schema helper: `tools/result_schema.py`
* Shared HTTP result utility helper: `tools/http_result_utils.py`
* Shared inventory candidate builder: `tools/inventory_candidate_builder.py`
* Refactored `safe_sitemap_parser_workflow`
* Refactored `safe_robots_securitytxt_workflow`
* Refactored `safe_js_endpoint_extraction_workflow`
* Refactored `safe_bounded_crawl_workflow`
* Refactored `safe_http_probe_workflow`
* Refactored `safe_security_headers_workflow`
* Refactored `safe_cors_observation_workflow`
* Refactored `safe_passive_recon_workflow`
* Split MCP wrappers into `mcp_tools/`
* Added MCP tool registration tests
* Workflow tests for v0.4/v0.5 behavior

---

## v0.5 Safety Statement

v0.5 did not add:

* Exploit automation
* Fuzzing
* Brute force
* Credential testing
* Form submission
* State-changing action
* Destructive action
* New external request behavior
* New request budgets
* New vulnerability validation

v0.5 only refactored existing safe workflows, standardized result construction, standardized safety metadata, and moved MCP wrappers into grouped registration modules.

---

## Current Exposed MCP Tools

LM Studio toolbox names must remain stable:

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

Low-level helpers such as raw HTTP probing, DNS lookup, storage utilities, validators, and parsers should not be exposed directly unless explicitly required and reviewed through the risk model.

---

## MCP Layer

Current MCP layer:

```text
server.py
mcp_tools/
```

`server.py` is now only the MCP composition root:

* Creates `FastMCP("Bug Bounty MCP Toolbox")`
* Imports grouped registration functions
* Calls registration functions
* Starts the MCP server

`server.py` must not:

* Send HTTP requests
* Implement workflow logic
* Parse HTML, JavaScript, XML, or URLs
* Build inventory candidates
* Modify request budgets
* Bypass scope guard
* Bypass risk gate
* Change report writer behavior

MCP wrapper groups:

```text
mcp_tools/scope_tools.py
    registers tool_check_scope

mcp_tools/risk_tools.py
    registers tool_evaluate_action_risk

mcp_tools/workflow_tools.py
    registers safe workflow wrappers

mcp_tools/report_tools.py
    registers report tools
```

All `mcp_tools/*` modules are thin wrappers. They delegate to existing tools or workflows and do not implement workflow logic directly.

---

## Layer Responsibilities

### Agent Layer

Location:

```text
agent/
```

Responsibilities:

* Risk evaluation
* Approval request construction
* Future planning and task routing

Rules:

* Must not send HTTP requests directly
* Must not bypass scope guard
* Must deny unknown tools by default
* Must require explicit approval for low/medium/high risk tools when policy requires it

### Workflow Layer

Location:

```text
workflows/
```

Responsibilities:

* Check scope before external requests
* Call low-level tools
* Call validators
* Save safe observations or candidate findings when designed to do so
* Return standardized or backward-compatible result objects
* Return safety metadata

Rules:

* No workflow may perform exploit automation
* No workflow may fuzz
* No workflow may brute force
* No workflow may perform credential testing
* No workflow may submit forms
* No workflow may perform state-changing or destructive actions
* No workflow may store cookies, tokens, secrets, personal data, payment data, or full sensitive response bodies

### Shared Helper Layer

Location:

```text
tools/safety_metadata.py
tools/result_schema.py
tools/http_result_utils.py
tools/inventory_candidate_builder.py
```

Responsibilities:

* Build consistent safety metadata
* Build stable workflow result shapes
* Normalize HTTP helper result handling
* Filter sensitive headers and body content from observations
* Build sanitized inventory candidates

Rules:

* Helpers must not call workflows unless explicitly designed and documented
* Helpers must not add external request behavior
* Helpers must not claim vulnerability confirmation

### Tool Layer

Location:

```text
tools/
```

Responsibilities:

* Low-level reusable utilities
* Scope checking
* HTTP probing
* Header extraction
* Report writing
* Logging
* Policy loading
* Skill loading
* Inventory utilities

### Validator Layer

Location:

```text
validators/
```

Responsibilities:

* Conservative classification
* False-positive reduction
* Triage priority
* Reportability guidance

Validators must not send requests, modify state, execute payloads, or make unsupported vulnerability claims.

---

## Request Budgets

Existing request budgets remain unchanged:

| Workflow | Risk level | Max requests |
| --- | --- | ---: |
| `safe_http_probe_workflow` | low | 1 |
| `safe_security_headers_workflow` | low | 1 |
| `safe_cors_observation_workflow` | low | 1 |
| `safe_passive_recon_workflow` | low | 3 |
| `safe_robots_securitytxt_workflow` | low | 3 |
| `safe_sitemap_parser_workflow` | low | 1 |
| `safe_js_endpoint_extraction_workflow` | medium | 31 |
| `safe_bounded_crawl_workflow` | medium | 30 |

v0.5 did not increase or add request budgets.

---

## Test Coverage

Current major tests:

```text
tests/test_mcp_tool_registration.py
tests/test_safe_passive_recon_workflow.py
tests/test_safe_cors_observation_workflow.py
tests/test_safe_security_headers_workflow.py
tests/test_safe_http_probe_workflow.py
tests/test_bounded_crawl_workflow.py
tests/test_js_endpoint_extraction_workflow.py
tests/test_robots_securitytxt_workflow.py
tests/test_sitemap_parser_workflow.py
tests/test_inventory_candidate_builder.py
tests/test_http_result_utils.py
tests/test_safety_metadata.py
tests/test_result_schema.py
tests/test_bounded_crawl_foundation.py
tests/test_attack_surface_inventory.py
tests/test_risk_gate.py
tests/test_skill_loader.py
```

Registration tests verify that MCP tool names and wrapper signatures remain stable without executing workflows or sending network traffic.

---

## Future v0.6 Direction

Future milestone:

```text
v0.6-controlled-validation
```

v0.6 is future work. It is the earliest milestone where controlled validation planning may begin.

Possible future v0.6 areas:

* Controlled open redirect observation
* Controlled exposed file observation
* Controlled GraphQL observation
* Authz / IDOR validation preparation

v0.6 must still use:

* Scope guard
* Risk gate
* Explicit approval
* Request limits
* Evidence rules
* Sensitive-data minimization
* Standard result schema
* Standard safety metadata

v0.6 must not become unrestricted exploit automation. The project must not claim it can automatically exploit or compromise targets.
