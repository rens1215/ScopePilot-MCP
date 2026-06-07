# Roadmap

## Purpose

This document records the version roadmap for `MCP_SERVER_FOR_LLM_HACKER`.

The roadmap explains what each version added, why it was needed, what safety boundary it introduced, and what the next stage should focus on.

The project goal is to build an AI-callable MCP toolbox for authorized, in-scope web security testing.

This roadmap does not describe unrestricted attack automation. Every stage must preserve scope guard, risk gate, approval rules, request limits, and sensitive-data minimization.

---

## Current Stable Version

```text
v0.5-core-refactor-and-result-standardization
```

---

## Version Summary

```text
v0.1-safe-observation-foundation
    Basic safe observation workflows.

v0.2-risk-gate-and-execution-policy
    Tool risk model, approval policy, and execution safety rules.

v0.3-runtime-skills-and-agent-guidance
    Runtime skills and AI-facing operational guidance.

v0.4-attack-surface-inventory
    Endpoint discovery, sitemap parsing, JS endpoint extraction, bounded crawling.

v0.5-core-refactor-and-result-standardization
    Shared helpers, standardized outputs, workflow refactor, thin MCP wrappers.

v0.6-controlled-validation
    Future work. Controlled validation planning for selected high-value findings.
```

---

# v0.1 — Safe Observation Foundation

## Goal

Build the first safe workflows that an AI agent can call through MCP.

## Why v0.1 Was Needed

Before the AI agent can reason about vulnerabilities, it needs safe ways to observe a target.

v0.1 established the earliest low-risk workflows:

* Check whether a target responds.
* Observe HTTP metadata.
* Observe security headers.
* Observe CORS behavior.
* Produce basic findings or observations.
* Avoid exploit behavior.

## Main Components

```text
safe_http_probe_workflow
safe_security_headers_workflow
safe_cors_observation_workflow
safe_passive_recon_workflow
```

## Capabilities Added

### Safe HTTP Probe

Purpose:

* Perform one scoped HTTP probe.
* Collect safe metadata:

  * status code
  * final URL
  * title
  * content type
  * body size
  * safe header summary
* Save an observation.

Request budget:

```text
1 request
```

### Safe Security Headers Workflow

Purpose:

* Observe common security headers.
* Check missing or present recommended headers.
* Produce observation or candidate finding.

Request budget:

```text
1 request
```

### Safe CORS Observation Workflow

Purpose:

* Send one harmless CORS observation request with a safe Origin header.
* Observe CORS response headers.
* Produce observation or candidate finding.

Request budget:

```text
1 request
```

### Safe Passive Recon Workflow

Purpose:

* Coordinate basic safe observation workflows.
* Combine HTTP probe, security headers, and CORS observation.
* Produce a passive recon summary.

Request budget:

```text
3 requests
```

## Safety Boundary

v0.1 did not include:

* Exploit automation
* Fuzzing
* Brute force
* Credential testing
* Form submission
* Crawling
* State-changing actions

## Result

v0.1 created the first AI-callable low-risk observation layer.

---

# v0.2 — Risk Gate and Execution Policy

## Goal

Add policy controls so the AI agent cannot freely execute tools without scope and risk checks.

## Why v0.2 Was Needed

Once the toolbox had multiple callable workflows, the project needed a clear rule system.

Without risk gate and approval policy, the AI agent could call tools out of order, call unknown tools, or perform actions that should require explicit approval.

v0.2 introduced the policy layer.

## Main Components

```text
agent/risk_gate.py
agent/approval_controller.py
config/tool_risk_profiles.json
docs/TOOL_RISK_MODEL.md
tool_evaluate_action_risk
```

## Capabilities Added

### Tool Risk Profiles

Each exposed tool is assigned metadata such as:

```text
risk_level
external_requests
default_requires_approval
max_requests
changes_state
uses_credentials
allowed_modes
```

### Risk Gate

Purpose:

* Evaluate whether a tool action is allowed.
* Deny unknown tools by default.
* Enforce approval rules.
* Enforce allowed modes.
* Surface request budget and risk information to the agent.

### Approval Controller

Purpose:

* Generate approval requests for tools requiring explicit user approval.
* Keep approval separate from execution.

### MCP Risk Evaluation Tool

Exposed tool:

```text
tool_evaluate_action_risk
```

Purpose:

* Let the AI agent evaluate risk before execution.
* Make the workflow order explicit:

  1. Check scope.
  2. Evaluate risk.
  3. Ask approval if required.
  4. Execute only if allowed.

## Safety Boundary

v0.2 added these rules:

* Unknown tools are denied.
* Blocked tools cannot be executed.
* Approval-required tools cannot run without approval.
* Tool risk must be evaluated before execution.
* Risk policy must not be bypassed by MCP wrappers.

## Result

v0.2 made the toolbox safer and more controllable by adding a policy layer.

---

# v0.3 — Runtime Skills and Agent Guidance

## Goal

Create AI-readable runtime guidance so the local LLM understands how to use the toolbox safely.

## Why v0.3 Was Needed

The project is not only a Python toolbox. It is meant to be used by an AI agent.

The AI needs operational rules:

* Which tool to call first.
* When approval is required.
* What actions are prohibited.
* How to interpret observations.
* How to avoid turning inventory into vulnerability claims.

v0.3 introduced runtime skills.

## Main Components

```text
skills/
skills/agent_runtime/
skills/codex_dev/
tools/skill_loader.py
docs/RUNTIME_SKILLS.md
tests/test_skill_loader.py
```

## Capabilities Added

### Runtime Skills

Purpose:

* Give the AI agent concise operational rules.
* Define safe execution order.
* Define prohibited behavior.
* Explain how to report observations.

### Codex Development Skills

Purpose:

* Guide Codex when modifying the project.
* Reinforce allowed file changes.
* Keep generated code aligned with architecture.
* Avoid unsafe or uncontrolled feature additions.

### Skill Loader

Purpose:

* Load skill files.
* Validate skill folder structure.
* Ensure runtime guidance is accessible.

## Safety Boundary

v0.3 reinforced:

* The AI must not exploit.
* The AI must not fuzz.
* The AI must not brute force.
* The AI must not use credentials unless a future explicitly authorized workflow supports it.
* The AI must not treat observations as confirmed vulnerabilities.
* The AI must use scope guard, risk gate, and approval rules.

## Result

v0.3 made the system more usable by an AI agent and easier for Codex to maintain safely.

---

# v0.4 — Attack Surface Inventory

## Goal

Build the first structured attack surface inventory capability.

## Why v0.4 Was Needed

Basic observation is not enough for automated security testing.

Before controlled validation, the AI must know:

* What endpoints exist.
* Where each endpoint came from.
* Whether each endpoint is same-scope.
* Whether each endpoint looks like frontend, API, auth, admin, documentation, static asset, or unknown.
* Which endpoints should be prioritized later.

v0.4 created bounded endpoint discovery without vulnerability validation.

## Main Components

```text
tools/url_normalizer.py
tools/endpoint_inventory.py
validators/inventory_validator.py
tools/js_endpoint_extractor.py
tools/html_link_extractor.py
tools/crawl_queue.py

workflows/safe_robots_securitytxt_workflow.py
workflows/safe_sitemap_parser_workflow.py
workflows/safe_js_endpoint_extraction_workflow.py
workflows/safe_bounded_crawl_workflow.py
```

## Capabilities Added

### URL Normalizer

Purpose:

* Normalize absolute and relative URLs.
* Reject unsupported schemes.
* Support consistent inventory candidate construction.

### Endpoint Inventory Builder

Purpose:

* Build structured endpoint inventory items.
* Preserve source and discovery method.
* Keep inventory separate from vulnerability proof.

### Inventory Validator

Purpose:

* Classify endpoint candidates conservatively.
* Add endpoint type, priority, confidence, and recommended next skill.
* Avoid claiming vulnerabilities.

### Robots / Security.txt Metadata Workflow

Purpose:

* Request:

  * `/robots.txt`
  * `/.well-known/security.txt`
  * `/sitemap.xml`
* Create metadata observations and inventory candidates.
* Avoid scanning robots `Disallow` paths.

Request budget:

```text
3 requests
```

### Sitemap Parser Workflow

Purpose:

* Request `/sitemap.xml`.
* Parse sitemap URLs.
* Normalize same-scope URLs.
* Convert extracted URLs into inventory candidates.
* Do not request sitemap-listed URLs.

Request budget:

```text
1 request
```

### JavaScript Endpoint Extraction Workflow

Purpose:

* Request target HTML.
* Extract same-scope script src values.
* Request bounded same-scope JS files.
* Statically extract API endpoint candidates.
* Do not execute JavaScript.
* Do not request extracted API endpoints.

Request budget:

```text
default: 1 HTML + 20 JS requests
hard cap: 1 HTML + 30 JS requests
total hard cap: 31 requests
```

### Bounded Crawl Workflow

Purpose:

* Perform bounded same-scope HTML crawling.
* Enforce max pages, max depth, and max requests.
* Extract anchor links.
* Add script src values as inventory candidates.
* Do not download JS.
* Do not submit forms.

Request budget:

```text
30 requests
```

## Safety Boundary

v0.4 did not include:

* Vulnerability validation
* Exploit attempts
* Fuzzing
* Brute force
* Credential testing
* Form submission
* State-changing actions
* JS execution
* API endpoint probing from JS extraction

## Result

v0.4 allowed the AI agent to build a high-signal attack surface map while staying bounded and non-destructive.

---

# v0.5 — Core Refactor and Result Standardization

## Goal

Refactor and standardize the existing v0.1–v0.4 system before adding controlled validation.

## Why v0.5 Was Needed

By the end of v0.4, the project had many workflows, helpers, validators, tests, docs, and MCP wrappers.

Without refactoring, future controlled validation would make the project hard to maintain and audit.

v0.5 focused on:

* Reducing duplicated workflow logic.
* Standardizing result structures.
* Standardizing safety metadata.
* Standardizing HTTP result handling.
* Standardizing inventory candidate building.
* Making `server.py` thinner.
* Keeping MCP tool names stable.

## Main Components Added

```text
tools/safety_metadata.py
tools/result_schema.py
tools/http_result_utils.py
tools/inventory_candidate_builder.py

mcp_tools/__init__.py
mcp_tools/scope_tools.py
mcp_tools/risk_tools.py
mcp_tools/workflow_tools.py
mcp_tools/report_tools.py
```

## Capabilities Added

### Shared Safety Metadata

File:

```text
tools/safety_metadata.py
```

Purpose:

* Build consistent safety metadata.
* Default to safe values.
* Include fields such as:

  * requests_sent
  * scan_level
  * fuzzing
  * bruteforce
  * exploitation
  * crawling
  * credentialed_request
  * state_changing

### Shared Result Schema

File:

```text
tools/result_schema.py
```

Purpose:

* Build stable workflow result objects.
* Support consistent fields:

  * target
  * stopped
  * reason
  * scope
  * observations
  * inventory_candidates
  * findings
  * errors
  * warnings
  * summary
  * safety

### HTTP Result Utilities

File:

```text
tools/http_result_utils.py
```

Purpose:

* Normalize HTTP helper failures.
* Extract content type.
* Summarize safe headers.
* Exclude sensitive headers.
* Exclude full response bodies.
* Build base HTTP observations.

### Inventory Candidate Builder

File:

```text
tools/inventory_candidate_builder.py
```

Purpose:

* Sanitize inventory evidence.
* Build validated inventory candidates.
* Attach conservative validator result.
* Avoid storing sensitive data.
* Avoid claiming vulnerability proof.

### Workflow Refactor

Refactored workflows:

```text
safe_sitemap_parser_workflow
safe_robots_securitytxt_workflow
safe_js_endpoint_extraction_workflow
safe_bounded_crawl_workflow
safe_http_probe_workflow
safe_security_headers_workflow
safe_cors_observation_workflow
safe_passive_recon_workflow
```

Refactor rule:

* Preserve existing behavior.
* Preserve request budgets.
* Preserve safety boundaries.
* Add standard output fields where useful.
* Do not add new attack capability.

### MCP Wrapper Split

Before v0.5:

```text
server.py contained many MCP wrappers
```

After v0.5:

```text
server.py
    MCP composition root only

mcp_tools/scope_tools.py
    tool_check_scope

mcp_tools/risk_tools.py
    tool_evaluate_action_risk

mcp_tools/workflow_tools.py
    safe workflow wrappers

mcp_tools/report_tools.py
    reporting wrappers
```

## Safety Boundary

v0.5 did not add:

* Exploit automation
* Vulnerability validation
* Fuzzing
* Brute force
* Credential testing
* Form submission
* State-changing actions
* Destructive actions
* New external request behavior
* New request budgets

## Result

v0.5 made the project more maintainable and prepared the codebase for future controlled validation.

---

# Future v0.6 — Controlled Validation

## Goal

Add carefully bounded validation planning and observation workflows for selected high-value inventory items.

## Why v0.6 Is Needed

v0.4 can discover and prioritize endpoints, but it does not validate vulnerabilities.

v0.6 should begin controlled validation, but only after v0.5 standardization is complete.

## Possible Scope

Future controlled validation may include:

```text
controlled_open_redirect_observation
controlled_exposed_file_observation
controlled_graphql_observation
controlled_authz_review_preparation
controlled_idor_validation_preparation
```

## Required Safety Controls

v0.6 must use:

* Scope guard
* Risk gate
* Explicit approval
* Request limits
* Evidence rules
* Sensitive-data minimization
* Standard result schema
* Standard safety metadata
* Clear stop conditions

## v0.6 Must Not Become

```text
unrestricted exploit automation
unrestricted exploit chaining
credential stuffing
brute force
DoS
mass fuzzing
destructive testing
real data exfiltration
automatic account abuse
```

## Current Status

```text
v0.6 is future work.
```

The project must not currently claim to automatically exploit, compromise, or fully validate vulnerabilities.
