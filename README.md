# ScopePilot MCP

**A safe and bounded AI-Agent security testing framework powered by Model Context Protocol.**

ScopePilot MCP is an AI-assisted security testing toolbox built around MCP tools.
It helps a local AI agent perform authorized, in-scope web security testing tasks such as scoped reconnaissance, attack surface inventory, controlled workflow execution, evidence organization, finding prioritization, finding summarization, and report draft generation.

This project is not an unrestricted attack automation tool.
All external actions are designed to pass through scope checks, risk evaluation, request limits, approval policy, workflow safety rules, standardized result schemas, and sensitive-data minimization.

---

## Current Stable Version

```text
v0.5-core-refactor-and-result-standardization
```

Current status:

* v0.1 safe observation workflows completed.
* v0.2 risk gate and execution policy completed.
* v0.3 runtime skills and agent guidance completed.
* v0.4 attack surface inventory completed.
* v0.5 core refactor and result standardization completed.
* v0.6 controlled validation is planned as future work.

---

## Project Goals

ScopePilot MCP aims to provide a safe MCP-based toolbox that allows an AI agent to:

* Check whether a target is in scope.
* Evaluate tool execution risk before running workflows.
* Request explicit approval when needed.
* Perform low-risk reconnaissance.
* Build an attack surface inventory.
* Extract endpoint candidates from robots.txt, sitemap.xml, JavaScript, and bounded crawling.
* Prioritize interesting endpoints for later validation.
* Summarize observations and candidate findings.
* Generate report drafts without automatic submission.

The project focuses on **authorized security testing only**.

---

## What This Project Does Not Do

ScopePilot MCP does not currently perform:

* Exploit automation
* Exploit chaining
* SQL injection exploitation
* XSS exploitation
* SSRF exploitation
* RCE exploitation
* Brute force
* Credential stuffing
* Denial-of-Service testing
* Mass fuzzing
* Unauthorized credentialed testing
* Form submission
* State-changing actions
* Real data exfiltration
* Automatic bounty submission

Current workflows are designed for safe reconnaissance, attack surface inventory, result organization, and report preparation.

Controlled validation is planned for future versions and must remain bounded, approved, and scope-aware.

---

## Core Safety Model

Every external workflow is expected to follow these rules:

1. Check target scope before sending requests.
2. Evaluate tool risk before execution.
3. Require approval when policy says so.
4. Enforce request budgets.
5. Avoid credential use.
6. Avoid state-changing behavior.
7. Avoid exploit, fuzzing, and brute force behavior.
8. Store only safe metadata.
9. Never store cookies, tokens, secrets, personal data, payment data, or full sensitive response bodies.
10. Return standardized safety metadata.

---

## Current MCP Tools

The current toolbox exposes the following MCP tools:

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

---

## Tool Overview

### Scope and Risk Tools

#### `tool_check_scope`

Checks whether a target is allowed by the local scope configuration.

Use this before any external workflow.

#### `tool_evaluate_action_risk`

Evaluates whether a tool action is allowed by the local risk policy.

It does not execute the target tool.
It only returns risk level, request budget, approval requirement, and allow/deny decision.

---

### Safe Observation Workflows

#### `tool_safe_http_probe_workflow`

Performs one low-risk HTTP observation request.

Typical output includes:

* status code
* final URL
* content type
* body size
* safe header summary
* endpoint classification metadata

Request budget:

```text
1 request
```

#### `tool_safe_security_headers_workflow`

Observes common security headers such as:

* Content-Security-Policy
* Strict-Transport-Security
* X-Frame-Options
* X-Content-Type-Options
* Referrer-Policy
* Permissions-Policy

Request budget:

```text
1 request
```

#### `tool_safe_cors_observation_workflow`

Performs one harmless CORS observation using a safe test origin.

Request budget:

```text
1 request
```

#### `tool_safe_passive_recon_workflow`

Coordinates safe HTTP probe, security header observation, and CORS observation.

Request budget:

```text
3 requests
```

---

### Attack Surface Inventory Workflows

#### `tool_safe_robots_securitytxt_workflow`

Requests fixed public metadata paths:

```text
/robots.txt
/.well-known/security.txt
/sitemap.xml
```

It does not request paths listed in `robots.txt`.

Request budget:

```text
3 requests
```

#### `tool_safe_sitemap_parser_workflow`

Requests `/sitemap.xml`, parses sitemap URLs, and converts in-scope URLs into inventory candidates.

It does not request URLs listed inside the sitemap.

Request budget:

```text
1 request
```

#### `tool_safe_js_endpoint_extraction_workflow`

Requests a target HTML page, extracts same-scope JavaScript files, and statically extracts endpoint candidates from JavaScript text.

It does not execute JavaScript.
It does not request API endpoints extracted from JavaScript.

Request budget:

```text
Default: 1 HTML + 20 JS requests
Hard cap: 1 HTML + 30 JS requests
Total hard cap: 31 requests
```

#### `tool_safe_bounded_crawl_workflow`

Performs bounded same-scope HTML crawling.

It enforces:

* max pages
* max depth
* max requests
* same-scope filtering
* HTML-only parsing
* no form submission
* no JavaScript download
* no JS endpoint probing

Request budget:

```text
30 requests
```

---

### Report Tools

#### `tool_summarize_findings`

Summarizes locally stored observations or findings.

It does not send external requests.

#### `tool_write_report_draft`

Creates a report draft from existing observations or findings.

It does not submit reports automatically.

---

## Architecture Overview

```text
User / Runtime AI Agent
    ↓
LM Studio MCP Client
    ↓
server.py
    ↓
mcp_tools/*
    ↓
Scope Tool / Risk Tool / Workflow Tool / Report Tool
    ↓
Scope Guard + Risk Gate + Approval Policy
    ↓
Safe Workflow
    ↓
Low-level Tools + Validators
    ↓
Standard Result Schema
    ↓
Storage / Summary / Report Draft
```

---

## Directory Structure

```text
.
├── agent/
│   ├── approval_controller.py
│   └── risk_gate.py
│
├── config/
│   ├── scope.example.json
│   ├── scan_policy.json
│   ├── false_positive_rules.json
│   └── tool_risk_profiles.json
│
├── data/
│   └── .gitkeep
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── ATTACK_SURFACE_INVENTORY.md
│   ├── RESULT_SCHEMA.md
│   ├── ROADMAP.md
│   ├── TEST_PLAN.md
│   ├── TOOL_RISK_MODEL.md
│   └── RUNTIME_SKILLS.md
│
├── mcp_tools/
│   ├── __init__.py
│   ├── scope_tools.py
│   ├── risk_tools.py
│   ├── workflow_tools.py
│   └── report_tools.py
│
├── skills/
│   ├── agent_runtime/
│   └── codex_dev/
│
├── tools/
│   ├── scope_guard.py
│   ├── http_probe.py
│   ├── security_headers.py
│   ├── endpoint_classifier.py
│   ├── priority_scorer.py
│   ├── finding_summarizer.py
│   ├── report_writer.py
│   ├── storage.py
│   ├── logger.py
│   ├── policy_loader.py
│   ├── skill_loader.py
│   ├── url_normalizer.py
│   ├── endpoint_inventory.py
│   ├── js_endpoint_extractor.py
│   ├── html_link_extractor.py
│   ├── crawl_queue.py
│   ├── safety_metadata.py
│   ├── result_schema.py
│   ├── http_result_utils.py
│   └── inventory_candidate_builder.py
│
├── validators/
│   ├── header_validator.py
│   ├── cors_validator.py
│   └── inventory_validator.py
│
├── workflows/
│   ├── safe_http_probe_workflow.py
│   ├── safe_security_headers_workflow.py
│   ├── safe_cors_observation_workflow.py
│   ├── safe_passive_recon_workflow.py
│   ├── safe_robots_securitytxt_workflow.py
│   ├── safe_sitemap_parser_workflow.py
│   ├── safe_js_endpoint_extraction_workflow.py
│   └── safe_bounded_crawl_workflow.py
│
├── tests/
├── server.py
├── README.md
└── requirements.txt
```

---

## Result Schema

Workflows are expected to return standardized dictionaries.

Minimum expected structure:

```json
{
  "target": "",
  "stopped": false,
  "reason": "",
  "scope": {},
  "observations": [],
  "inventory_candidates": [],
  "findings": [],
  "errors": [],
  "warnings": [],
  "summary": {},
  "safety": {
    "requests_sent": 0,
    "scan_level": "safe",
    "fuzzing": false,
    "bruteforce": false,
    "exploitation": false,
    "crawling": false,
    "credentialed_request": false,
    "state_changing": false
  }
}
```

See:

```text
docs/RESULT_SCHEMA.md
```

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/ScopePilot-MCP.git
cd ScopePilot-MCP
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Linux / macOS:

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

---

## Configuration

### Scope Configuration

Before running any workflow, configure your authorized scope.

Recommended public example file:

```text
config/scope.example.json
```

Example:

```json
{
  "allowed_domains": [
    "example.com"
  ],
  "blocked_domains": [],
  "default_allow": false
}
```

For local private testing, copy it to:

```text
config/scope.json
```

Do not commit private scope targets to a public repository.

---

## Running the MCP Server

```bash
python server.py
```

The server registers MCP tools through:

```text
mcp_tools/scope_tools.py
mcp_tools/risk_tools.py
mcp_tools/workflow_tools.py
mcp_tools/report_tools.py
```

`server.py` is intentionally kept as a thin MCP composition root.

---

## Recommended AI Agent Tool Flow

For an in-scope target, the runtime AI agent should follow this order:

```text
1. tool_check_scope
2. tool_evaluate_action_risk
3. Ask for approval if required
4. Execute selected safe workflow
5. Summarize observations
6. Recommend next safe step
```

Example attack surface inventory sequence:

```text
tool_check_scope
tool_evaluate_action_risk
tool_safe_robots_securitytxt_workflow
tool_safe_sitemap_parser_workflow
tool_safe_js_endpoint_extraction_workflow
tool_safe_bounded_crawl_workflow
tool_summarize_findings
```

---

## Testing

Run full regression tests before merging or tagging:

```powershell
python tests/test_mcp_tool_registration.py
python tests/test_safe_passive_recon_workflow.py
python tests/test_safe_cors_observation_workflow.py
python tests/test_safe_security_headers_workflow.py
python tests/test_safe_http_probe_workflow.py
python tests/test_bounded_crawl_workflow.py
python tests/test_js_endpoint_extraction_workflow.py
python tests/test_robots_securitytxt_workflow.py
python tests/test_sitemap_parser_workflow.py
python tests/test_inventory_candidate_builder.py
python tests/test_http_result_utils.py
python tests/test_safety_metadata.py
python tests/test_result_schema.py
python tests/test_bounded_crawl_foundation.py
python tests/test_attack_surface_inventory.py
python tests/test_risk_gate.py
python tests/test_skill_loader.py
```

More details:

```text
docs/TEST_PLAN.md
```

---

## Roadmap

Current version:

```text
v0.5-core-refactor-and-result-standardization
```

Planned next version:

```text
v0.6-controlled-validation
```

Future versions may add:

* validation plan builder
* evidence sanitizer
* controlled open redirect observation
* controlled exposed file observation
* controlled GraphQL observation
* authz / IDOR validation preparation
* agent planner
* execution state tracking
* evidence pipeline
* report template system

More details:

```text
docs/ROADMAP.md
```

---

## Security and Ethics

This project is intended only for:

* authorized security testing
* in-scope bug bounty testing
* lab environments
* defensive security research
* educational security engineering

Do not use this project against targets you do not own or do not have permission to test.

The project intentionally avoids unrestricted exploitation, destructive testing, credential attacks, DoS, mass fuzzing, and automatic data exfiltration.

---

## Disclaimer

ScopePilot MCP is a security testing framework for authorized and in-scope use only.

The maintainers and users are responsible for ensuring that all testing activity complies with applicable laws, program rules, and authorization boundaries.

This project does not provide permission to test third-party systems.

---

## License

This project is licensed under the MIT License.