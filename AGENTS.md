# AGENTS.md

## Project Name

```text
ScopePilot MCP
```

## Project Goal

ScopePilot MCP is a safe and bounded AI-Agent security testing framework powered by Model Context Protocol.

The project provides an MCP toolbox that allows a local AI agent to perform authorized, in-scope web security testing tasks such as:

* scope checking
* risk evaluation
* approval-aware workflow execution
* safe reconnaissance
* attack surface inventory
* evidence organization
* finding prioritization
* finding summarization
* report draft generation

This project is not an unrestricted attack automation tool.

Every external action must follow:

* scope guard
* risk gate
* approval policy
* request limits
* workflow safety rules
* result schema
* sensitive-data minimization

---

## Current Stable Version

```text
v0.5-core-refactor-and-result-standardization
```

Completed capabilities through v0.5:

* MCP server integration with LM Studio
* Scope guard
* Risk gate
* Approval controller
* Tool risk profiles
* Runtime skill loader
* Runtime agent skill definitions
* Safe HTTP probe workflow
* Safe security headers workflow
* Safe CORS observation workflow
* Safe passive recon workflow
* Safe robots/security.txt/sitemap metadata workflow
* Safe sitemap parser workflow
* Safe JavaScript endpoint extraction workflow
* Safe bounded in-scope crawl workflow
* Attack surface inventory foundation
* URL normalizer
* Endpoint inventory builder
* Inventory validator
* JavaScript endpoint extractor
* HTML link extractor
* Crawl queue
* Shared safety metadata helper
* Shared result schema helper
* Shared HTTP result utility helper
* Shared inventory candidate builder
* Refactored workflows using shared helpers
* Split MCP wrappers into `mcp_tools/`
* MCP tool registration tests
* Roadmap, test plan, and result schema documentation

---

## Next Milestone

```text
v0.6-controlled-validation
```

v0.6 should focus on controlled validation planning and bounded observation workflows.

Possible v0.6 areas:

* validation plan builder
* evidence sanitizer
* controlled open redirect observation
* controlled exposed file observation
* controlled GraphQL observation
* authz / IDOR validation preparation

v0.6 must not become unrestricted exploit automation.

---

## Current Exposed MCP Tools

These tool names must remain stable unless explicitly requested:

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

Do not rename MCP tools without updating:

* `mcp_tools/`
* `config/tool_risk_profiles.json`
* tests
* docs
* README

---

## Architecture Rules

### MCP Layer

Location:

```text
server.py
mcp_tools/
```

Rules:

* `server.py` must stay thin.
* `server.py` should only create the MCP app, register tool groups, and run the server.
* `server.py` must not contain workflow logic.
* `server.py` must not send raw HTTP requests.
* `mcp_tools/*` should only contain thin MCP wrappers.
* MCP wrappers must not bypass scope guard, risk gate, or workflow safety rules.

Current grouping:

```text
mcp_tools/scope_tools.py
    tool_check_scope

mcp_tools/risk_tools.py
    tool_evaluate_action_risk

mcp_tools/workflow_tools.py
    safe workflow wrappers

mcp_tools/report_tools.py
    report wrappers
```

---

### Agent Layer

Location:

```text
agent/
```

Responsibilities:

* risk evaluation
* approval request construction
* future planning
* future execution state
* future task routing

Rules:

* Agent layer must not directly send HTTP requests.
* Agent layer must not bypass `scope_guard`.
* Agent layer must not bypass `risk_gate`.
* Unknown tools must fail closed.
* Medium-risk and high-risk actions require explicit approval.

---

### Workflow Layer

Location:

```text
workflows/
```

Responsibilities:

* check scope before external requests
* enforce request budgets
* call low-level tools
* call validators
* produce standardized results
* return safety metadata
* avoid sensitive-data storage

Rules:

* Every external workflow must call `check_scope()` before sending requests.
* Out-of-scope targets must return `requests_sent=0`.
* Workflows must not perform unrestricted crawling.
* Workflows must not exploit, fuzz, brute force, or perform credential attacks.
* Workflows must not submit forms.
* Workflows must not perform state-changing actions.
* Workflows must not store cookies, tokens, secrets, personal data, payment data, or full sensitive response bodies.
* Workflows should use shared helpers where possible.

Shared helpers:

```text
tools/safety_metadata.py
tools/result_schema.py
tools/http_result_utils.py
tools/inventory_candidate_builder.py
```

---

### Tool Layer

Location:

```text
tools/
```

Responsibilities:

* reusable low-level utilities
* HTTP probing
* header extraction
* URL normalization
* inventory building
* endpoint extraction
* logging
* storage
* policy loading
* skill loading
* report writing

Rules:

* Tools should be deterministic where possible.
* Tools should not decide final reportability alone.
* Tools that can send requests should normally be called through workflows.
* Tools must not store sensitive data.
* Tools must not bypass workflow safety boundaries.

---

### Validator Layer

Location:

```text
validators/
```

Responsibilities:

* conservative classification
* false-positive reduction
* reportability guidance
* validation result normalization

Validators must not:

* send HTTP requests
* modify state
* store findings
* execute payloads
* make unsupported vulnerability claims

Validator output should remain conservative:

```text
observation
candidate_finding
needs_manual_validation
confirmed_finding only when future controlled validation policy allows it
```

---

### Config Layer

Location:

```text
config/
```

Important files:

```text
config/scope.json
config/scan_policy.json
config/false_positive_rules.json
config/tool_risk_profiles.json
```

Rules:

* `scope.json` defines authorized targets.
* `tool_risk_profiles.json` defines tool risk levels.
* Unknown tools must be denied by default.
* New MCP tools must have risk profiles before exposure.
* Real private scope files should not be committed to public repositories.

For public GitHub repositories, prefer:

```text
config/scope.example.json
```

and keep real scope files local.

---

### Data Layer

Location:

```text
data/
```

Runtime files may include:

```text
data/findings.jsonl
data/evidence.jsonl
data/endpoint_inventory.jsonl
data/mcp.log
```

Rules:

* Runtime data must not be committed.
* Only `data/.gitkeep` should be committed.
* Findings and evidence must not include cookies, tokens, secrets, personal data, payment data, or full sensitive response bodies.
* Evidence should favor metadata, hashes, summaries, and reproducible steps.

---

### Documentation Layer

Location:

```text
docs/
```

Important files:

```text
docs/ARCHITECTURE.md
docs/ATTACK_SURFACE_INVENTORY.md
docs/RESULT_SCHEMA.md
docs/ROADMAP.md
docs/TEST_PLAN.md
docs/TOOL_RISK_MODEL.md
docs/RUNTIME_SKILLS.md
```

Rules:

* Architecture docs must reflect the current stable version.
* Roadmap must separate inventory, refactor, and controlled validation stages.
* Result schema must guide future workflow output.
* Test plan must list regression tests and safety expectations.
* Docs must not claim the project can automatically compromise targets.

---

## Standard Result Rules

Workflows should return a dictionary with these fields whenever possible:

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

Reference:

```text
docs/RESULT_SCHEMA.md
```

Rules:

* Do not remove backward-compatible fields.
* Do not under-report request counts.
* Do not store full response bodies.
* Do not store sensitive headers.
* Do not claim confirmed vulnerabilities unless future controlled validation policy explicitly allows it.

---

## Safety Rules

The project must not implement or expose:

* unrestricted exploit automation
* exploit chaining
* SQL injection exploitation
* XSS exploitation
* SSRF exploitation
* RCE exploitation
* brute force
* credential stuffing
* DoS
* mass fuzzing
* unauthorized credentialed testing
* form submission
* state-changing actions
* real data exfiltration
* automatic bounty submission

Allowed current behavior:

* safe reconnaissance
* bounded attack surface inventory
* static endpoint extraction
* bounded same-scope crawling
* conservative observation
* finding summarization
* report draft generation

---

## Risk Levels

### safe

No external request.

Examples:

* scope check
* risk evaluation
* finding summarization
* report draft generation
* local helper functions

### low

Limited, non-destructive external request.

Examples:

* safe HTTP probe
* security headers observation
* CORS observation
* passive recon
* robots/security.txt observation
* sitemap parser

### medium

Multiple bounded requests or more sensitive inventory collection.

Examples:

* JavaScript endpoint extraction
* bounded crawl
* future controlled open redirect observation
* future controlled GraphQL observation

### high

Sensitive workflows requiring credentials, account setup, or authorization-specific validation.

Examples:

* future authenticated authz validation
* future IDOR validation
* future authenticated API comparison

### blocked

Never automate.

Examples:

* brute force
* credential stuffing
* DoS
* mass fuzzing
* destructive testing
* unrestricted exploit chains
* real data exfiltration

---

## Coding Rules

* Keep code changes small and reviewable.
* Add comments for security boundaries, risk decisions, workflow phases, and fail-closed behavior.
* Public functions should include docstrings explaining purpose, inputs, outputs, and safety constraints.
* Avoid noisy comments that simply repeat obvious code.
* Prefer deterministic Python logic over LLM judgment for validation.
* Prefer workflow-level MCP tools over exposing low-level tools.
* Do not expose new MCP tools unless explicitly requested.
* Do not modify `scope_guard.py` unless explicitly requested.
* Do not modify request budgets unless explicitly documented and tested.
* Do not change workflow behavior during refactor unless explicitly requested.
* Add or update tests when behavior changes.
* Do not commit runtime files.
* Do not commit secrets.
* When uncertain, update docs first instead of changing runtime code.

---

## Test Rules

Tests should protect safety boundaries.

Every external workflow test should verify:

* out-of-scope target sends 0 requests
* request budget is enforced
* helper exception does not crash
* helper non-dict result does not crash
* sensitive data is not stored
* full response body is not stored
* no fuzzing
* no brute force
* no exploit
* no credentialed request
* no state-changing behavior

Full regression tests are listed in:

```text
docs/TEST_PLAN.md
```

---

## Codex Task Rules

Codex must work in small steps.

For each task:

1. Read this file first.
2. Read relevant docs under `docs/`.
3. Modify only files explicitly allowed by the user.
4. Do not modify unrelated files.
5. Do not expose new MCP tools unless explicitly requested.
6. Do not add exploit, fuzzing, brute force, credential attack, or destructive validation logic.
7. If a task requires a new workflow, also add or update tests.
8. If a task adds a new MCP tool, also update risk profile, tests, and docs.
9. If uncertain, update docs first instead of changing runtime code.
10. Explain what changed.
11. Explain how to test it.

---

## Current Development Direction

Current stable version:

```text
v0.5-core-refactor-and-result-standardization
```

Recommended next milestone:

```text
v0.6-controlled-validation
```

Before starting v0.6:

* Ensure v0.5 is merged into `main`.
* Tag v0.5.
* Confirm README, AGENTS.md, architecture docs, roadmap, result schema, and test plan are updated.
* Confirm `.gitignore` excludes runtime data and secrets.
* Confirm public repo does not contain private scope, cookies, tokens, logs, or findings.

v0.6 should start with documentation and planning before adding controlled validation workflows.

Recommended first v0.6 task:

```text
validation plan builder
```

This should be safe and local-only before any new external validation workflow is added.
