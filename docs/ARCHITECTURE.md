# Architecture

## Project Name

```text
MCP_SERVER_FOR_LLM_HACKER
```

## System Goal

This project is an AI-assisted authorized web security testing platform built around MCP tools.

The system helps an AI agent perform scoped reconnaissance, attack surface inventory, evidence organization, finding prioritization, finding summarization, and reproducible report preparation.

The system must operate only on explicitly authorized in-scope targets.

This project is not an unrestricted attack automation tool. Every external action must pass scope validation, risk policy, workflow safety rules, and approval rules where required.

---

## Current Stable Version

Current stable version:

```text
v0.4-attack-surface-inventory
```

Completed through v0.4:

* MCP server integration
* Scope guard
* Safe HTTP probe workflow
* Safe security headers workflow
* Safe CORS observation workflow
* Safe passive recon workflow
* Endpoint classifier
* Header validator
* CORS validator
* Priority scorer
* Finding summarizer
* Policy loader
* Tool risk profiles
* Risk gate
* Approval controller
* Risk evaluation MCP tool
* Tool risk model documentation
* Runtime skill loader
* Runtime skill loader tests
* Runtime agent skill definitions
* Runtime skill documentation
* Runtime skill folder structure
* Attack surface inventory foundation
* URL normalizer
* Endpoint inventory builder
* Inventory validator
* Safe robots/security.txt/sitemap metadata workflow
* Safe sitemap parser workflow
* JavaScript endpoint extractor
* Safe JavaScript endpoint extraction workflow
* HTML link extractor
* Crawl queue
* Safe bounded in-scope crawl workflow
* Risk profiles for v0.4 tools
* MCP wrappers for v0.4 tools
* v0.4 workflow tests
* Git version control
* Logging
* Simplified LM Studio toolbox

Current exposed MCP tools:

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

## Next Architecture Target

Next milestone:

```text
v0.5-core-refactor-and-result-standardization
```

The purpose of v0.5 is to refactor and integrate the existing v0.1–v0.4 features before adding controlled validation.

v0.5 should make the project easier to maintain, easier to test, easier for Codex to modify, and easier for the runtime AI agent to use safely.

v0.5 is not a new vulnerability-testing phase.

v0.5 must not add exploit automation, controlled validation, fuzzing, brute force, credential testing, form submission, state-changing actions, or destructive behavior.

The original controlled-validation milestone is moved to:

```text
v0.6-controlled-validation
```

---

## Why v0.5 Exists

The project now contains multiple layers:

* MCP wrappers
* Scope guard
* Risk gate
* Approval controller
* Safe workflows
* Inventory workflows
* Runtime skills
* Validators
* Storage
* Reporting
* Tests
* Documentation

If controlled validation is added before refactoring, the project will become harder to audit and maintain.

v0.5 exists to solve these problems:

* `server.py` is becoming too large.
* Workflow result shapes are not fully standardized.
* Safety metadata is duplicated across workflows.
* HTTP error handling is duplicated across workflows.
* Inventory candidate creation is duplicated across workflows.
* Tests are growing and need clearer organization.
* Future v0.6 validation workflows need stable shared primitives.

v0.5 should improve internal structure without changing the safety model.

---

## v0.5 Scope

v0.5 should focus on refactoring and integration only.

Recommended v0.5 modules:

```text
mcp_tools/
mcp_tools/__init__.py
mcp_tools/scope_tools.py
mcp_tools/risk_tools.py
mcp_tools/workflow_tools.py
mcp_tools/report_tools.py

tools/safety_metadata.py
tools/http_result_utils.py
tools/inventory_candidate_builder.py
tools/result_schema.py

tests/test_safety_metadata.py
tests/test_http_result_utils.py
tests/test_inventory_candidate_builder.py
tests/test_result_schema.py

docs/REFACTORING_PLAN.md
docs/RESULT_SCHEMA.md
```

Not every file must be implemented at once. v0.5 should be built in small, reviewable steps.

Recommended implementation order:

```text
Step 1: Define shared result and safety metadata helpers
Step 2: Extract shared HTTP result handling helpers
Step 3: Extract inventory candidate builder
Step 4: Refactor workflows to use shared helpers one group at a time
Step 5: Split MCP wrappers out of server.py
Step 6: Update tests and docs
```

---

## v0.5 Non-Goals

Do not implement these in v0.5:

```text
exploit automation
exploit chaining
SQL injection exploitation
IDOR validation
authentication bypass testing
credentialed testing
brute force
credential stuffing
DoS
mass fuzzing
state-changing validation
destructive action
real data exfiltration
automatic account testing
automatic vulnerability reporting
controlled open redirect validation
controlled exposed file validation
controlled GraphQL validation
controlled authz validation
controlled IDOR validation
```

These belong to future v0.6 or later controlled-validation phases.

---

## v0.5 Safety Rules

v0.5 must preserve all existing safety boundaries:

* Do not weaken scope checks.
* Do not bypass risk gate.
* Do not bypass approval controller.
* Do not increase request limits unless explicitly documented and tested.
* Do not add new external-request behavior.
* Do not add new MCP tools unless the refactor requires moving existing wrappers.
* Do not change existing workflow behavior unless the change is required for standardization and tests prove compatibility.
* Do not store sensitive data.
* Do not save cookies, tokens, secrets, personal data, payment data, or full sensitive response bodies.
* Do not add exploit payloads.
* Do not add brute-force logic.
* Do not add credential attack logic.
* Do not add destructive or state-changing behavior.

---

## Current v0.4 Architecture Summary

v0.4 completed attack surface inventory.

Attack surface inventory answers:

```text
What endpoints exist?
Where did each endpoint come from?
What type of endpoint is it?
How valuable is it for later validation?
What skill might be relevant next?
What safety constraints apply?
```

v0.4 workflows:

```text
safe_robots_securitytxt_workflow.py
safe_sitemap_parser_workflow.py
safe_js_endpoint_extraction_workflow.py
safe_bounded_crawl_workflow.py
```

v0.4 tools:

```text
url_normalizer.py
endpoint_inventory.py
js_endpoint_extractor.py
html_link_extractor.py
crawl_queue.py
```

v0.4 validator:

```text
inventory_validator.py
```

v0.4 request budgets:

```text
safe_robots_securitytxt_workflow: max 3 requests
safe_sitemap_parser_workflow: max 1 request
safe_js_endpoint_extraction_workflow: max 31 requests
safe_bounded_crawl_workflow: max 30 requests
```

v0.4 remains inventory-only. It does not prove vulnerability impact.

---

## Desired v0.5 Architecture

### Before v0.5

```text
server.py
    contains many MCP wrappers

workflows/
    each workflow has its own safety metadata logic
    each workflow has its own HTTP error handling
    each workflow has its own inventory candidate building logic

tools/
    contains useful utilities but shared workflow helpers are still duplicated
```

### After v0.5

```text
server.py
    starts MCP server
    imports/registers grouped MCP tools
    contains minimal direct wrapper logic

mcp_tools/
    contains MCP wrapper groups

tools/safety_metadata.py
    standardizes safety metadata

tools/http_result_utils.py
    standardizes HTTP helper result handling

tools/inventory_candidate_builder.py
    standardizes inventory candidate construction and validation

tools/result_schema.py
    standardizes workflow result shape

workflows/
    use shared helpers
    remain behaviorally compatible
```

---

## High-Level Execution Flow

Current intended runtime flow:

```text
User Request
    ↓
MCP Tool Wrapper
    ↓
Risk Gate / Approval Controller
    ↓
Safe Workflow
    ↓
Scope Guard
    ↓
Low-level Tool
    ↓
Validator
    ↓
Finding / Inventory Storage
    ↓
Summary / Report
```

v0.5 should not change this behavior.

v0.5 should only make the implementation cleaner:

```text
User Request
    ↓
server.py
    ↓
mcp_tools/*
    ↓
Workflow
    ↓
Shared Helpers
    ↓
Low-level Tool / Validator
    ↓
Standardized Result
```

---

## Layered Architecture

```text
MCP Layer
    server.py
    mcp_tools/

Agent Layer
    risk_gate
    approval_controller
    future planner
    future execution_state
    future task_router

Workflow Layer
    safe_http_probe_workflow
    safe_security_headers_workflow
    safe_cors_observation_workflow
    safe_passive_recon_workflow
    safe_robots_securitytxt_workflow
    safe_sitemap_parser_workflow
    safe_js_endpoint_extraction_workflow
    safe_bounded_crawl_workflow

Shared Helper Layer
    safety_metadata
    http_result_utils
    inventory_candidate_builder
    result_schema

Tool Layer
    scope_guard
    http_probe
    security_headers
    endpoint_classifier
    priority_scorer
    finding_summarizer
    storage
    logger
    policy_loader
    skill_loader
    url_normalizer
    endpoint_inventory
    js_endpoint_extractor
    html_link_extractor
    crawl_queue

Validator Layer
    header_validator
    cors_validator
    inventory_validator
    future exposed_file_validator
    future open_redirect_validator
    future authz_validator
    future idor_validator

Skill Layer
    skills/agent_runtime
    skills/codex_dev

Config Layer
    scope
    scan policy
    false positive rules
    tool risk profiles

Data Layer
    findings
    evidence
    logs
    endpoint inventory

Report Layer
    report writer
    future report templates
```

---

## Recommended Directory Structure

```text
MCP_SERVER_FOR_LLM_HACKER/
├── agent/
│   ├── __init__.py
│   ├── risk_gate.py
│   ├── approval_controller.py
│   ├── planner.py                  # future
│   ├── execution_state.py          # future
│   └── task_router.py              # future
│
├── mcp_tools/
│   ├── __init__.py                 # v0.5
│   ├── scope_tools.py              # v0.5
│   ├── risk_tools.py               # v0.5
│   ├── workflow_tools.py           # v0.5
│   └── report_tools.py             # v0.5
│
├── config/
│   ├── scope.json
│   ├── scan_policy.json
│   ├── false_positive_rules.json
│   └── tool_risk_profiles.json
│
├── data/
│   ├── .gitkeep
│   ├── findings.jsonl
│   ├── evidence.jsonl
│   ├── endpoint_inventory.jsonl
│   └── mcp.log
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── ATTACK_SURFACE_INVENTORY.md
│   ├── FINDING_SCHEMA.md
│   ├── RESULT_SCHEMA.md            # v0.5
│   ├── REFACTORING_PLAN.md         # v0.5
│   ├── ROADMAP.md
│   ├── TEST_PLAN.md
│   ├── TOOL_RISK_MODEL.md
│   └── RUNTIME_SKILLS.md
│
├── skills/
│   ├── agent_runtime/
│   └── codex_dev/
│
├── tools/
│   ├── __init__.py
│   ├── scope_guard.py
│   ├── http_probe.py
│   ├── security_headers.py
│   ├── endpoint_classifier.py
│   ├── priority_scorer.py
│   ├── finding_summarizer.py
│   ├── storage.py
│   ├── logger.py
│   ├── policy_loader.py
│   ├── skill_loader.py
│   ├── url_normalizer.py
│   ├── endpoint_inventory.py
│   ├── js_endpoint_extractor.py
│   ├── html_link_extractor.py
│   ├── crawl_queue.py
│   ├── safety_metadata.py          # v0.5
│   ├── http_result_utils.py        # v0.5
│   ├── inventory_candidate_builder.py # v0.5
│   └── result_schema.py            # v0.5
│
├── validators/
│   ├── __init__.py
│   ├── header_validator.py
│   ├── cors_validator.py
│   ├── inventory_validator.py
│   ├── exposed_file_validator.py    # future
│   ├── open_redirect_validator.py   # future
│   └── authz_validator.py           # future
│
├── workflows/
│   ├── __init__.py
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
│   ├── test_risk_gate.py
│   ├── test_skill_loader.py
│   ├── test_attack_surface_inventory.py
│   ├── test_robots_securitytxt_workflow.py
│   ├── test_sitemap_parser_workflow.py
│   ├── test_js_endpoint_extraction_workflow.py
│   ├── test_bounded_crawl_foundation.py
│   ├── test_bounded_crawl_workflow.py
│   ├── test_safety_metadata.py      # v0.5
│   ├── test_http_result_utils.py    # v0.5
│   ├── test_inventory_candidate_builder.py # v0.5
│   └── test_result_schema.py        # v0.5
│
├── server.py
├── requirements.txt
├── README.md
└── AGENTS.md
```

Some files listed above are v0.5 targets and may not exist yet.

---

## MCP Layer

Location:

```text
server.py
mcp_tools/
```

Purpose:

* Register MCP tools.
* Expose controlled workflows to LM Studio.
* Keep a stable interface between the local LLM and Python execution logic.

Current issue:

```text
server.py contains many wrapper functions and is becoming large.
```

v0.5 goal:

```text
Move MCP wrapper groups into mcp_tools/.
Keep server.py as a thin MCP startup and registration file.
```

Recommended grouping:

```text
mcp_tools/scope_tools.py
    tool_check_scope

mcp_tools/risk_tools.py
    tool_evaluate_action_risk

mcp_tools/workflow_tools.py
    tool_safe_http_probe_workflow
    tool_safe_security_headers_workflow
    tool_safe_cors_observation_workflow
    tool_safe_passive_recon_workflow
    tool_safe_robots_securitytxt_workflow
    tool_safe_sitemap_parser_workflow
    tool_safe_js_endpoint_extraction_workflow
    tool_safe_bounded_crawl_workflow

mcp_tools/report_tools.py
    tool_summarize_findings
    tool_write_report_draft
```

Rules:

* `server.py` should not send HTTP requests.
* `server.py` should not implement workflow logic.
* `mcp_tools/*` should remain thin wrappers.
* `mcp_tools/*` should not bypass scope guard.
* `mcp_tools/*` should not bypass risk gate.
* Existing tool names must remain stable.
* Existing LM Studio behavior should remain compatible.

---

## Standard Workflow Result Schema

v0.5 should define a standard workflow result shape.

Location:

```text
tools/result_schema.py
docs/RESULT_SCHEMA.md
```

Recommended base shape:

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
    "scan_level": "safe | low-risk | medium-risk | high-risk | blocked",
    "fuzzing": false,
    "bruteforce": false,
    "exploitation": false,
    "crawling": false,
    "credentialed_request": false,
    "state_changing": false
  }
}
```

Rules:

* Existing workflows do not need to become identical in one step.
* Refactor gradually.
* Preserve existing keys where LM Studio currently relies on them.
* Standardization must not break tests.
* New helper functions should make future workflow output more consistent.

Possible helper functions:

```text
build_workflow_result(...)
build_blocked_result(...)
append_observation(...)
append_error(...)
```

---

## Standard Safety Metadata

v0.5 should extract repeated safety metadata creation into:

```text
tools/safety_metadata.py
```

Recommended helper:

```text
build_safety_metadata(
    requests_sent=0,
    scan_level="low-risk",
    fuzzing=False,
    bruteforce=False,
    exploitation=False,
    crawling=False,
    credentialed_request=False,
    state_changing=False
)
```

Rules:

* Must default to safe values.
* Must not hide risky behavior.
* Must support existing safety fields.
* Must not change existing workflow behavior unless tests are updated intentionally.
* Must include `state_changing=false` for future compatibility.

---

## Standard HTTP Result Handling

v0.5 should extract repeated HTTP helper handling into:

```text
tools/http_result_utils.py
```

Current repeated patterns:

* `http_probe` is unavailable.
* `http_probe` raises exception.
* `http_probe` returns non-dict.
* Result is blocked.
* Result has error.
* Content-Type extraction.
* Safe header summary.
* Body text extraction.

Recommended helpers:

```text
safe_http_probe_call(url: str) -> tuple[dict, bool]
get_content_type(probe: dict) -> str
headers_summary(headers: dict | None) -> dict
probe_body_text(probe: dict) -> str
base_http_observation(...)
is_allowed_content_type(...)
```

Rules:

* Must not send requests except through the existing `http_probe` helper.
* Must not save sensitive headers.
* Must not save cookies, authorization headers, tokens, secrets, personal data, or full sensitive response bodies.
* Must convert exceptions and malformed results into structured request_error observations.
* Must preserve current workflow behavior.

---

## Standard Inventory Candidate Builder

v0.5 should extract repeated inventory candidate construction into:

```text
tools/inventory_candidate_builder.py
```

Current repeated logic:

* Build inventory item.
* Add safe evidence metadata.
* Run `validate_inventory_item`.
* Copy endpoint_type, priority, confidence, recommended_next_skill.
* Add validator_result.
* Avoid sensitive data.

Recommended helper:

```text
build_validated_inventory_candidate(
    target: str,
    raw_url: str,
    normalized_url: str,
    source: str,
    discovered_by: str,
    evidence: dict,
    notes: str = ""
) -> dict
```

Rules:

* Must not send requests.
* Must not validate vulnerabilities.
* Must not claim impact.
* Must sanitize evidence.
* Must not store sensitive data.
* Must preserve current candidate fields.

---

## Workflow Refactor Plan

Refactor workflows gradually.

Recommended order:

```text
Step 1: Add shared helper modules and tests.
Step 2: Refactor one simple workflow first, such as safe_sitemap_parser_workflow.
Step 3: Refactor safe_robots_securitytxt_workflow.
Step 4: Refactor safe_js_endpoint_extraction_workflow.
Step 5: Refactor safe_bounded_crawl_workflow.
Step 6: Refactor older workflows only if needed:
        safe_http_probe_workflow
        safe_security_headers_workflow
        safe_cors_observation_workflow
        safe_passive_recon_workflow
```

Rules:

* Refactor only one workflow group at a time.
* Run tests after each workflow refactor.
* Keep outputs backward compatible unless intentionally documented.
* Do not change request budgets.
* Do not add new external requests.
* Do not add new risk profiles unless exposing new tools.
* Do not add new vulnerability validation.

---

## Test Strategy for v0.5

Minimum tests that must continue passing:

```text
tests/test_bounded_crawl_workflow.py
tests/test_bounded_crawl_foundation.py
tests/test_js_endpoint_extraction_workflow.py
tests/test_sitemap_parser_workflow.py
tests/test_robots_securitytxt_workflow.py
tests/test_attack_surface_inventory.py
tests/test_risk_gate.py
tests/test_skill_loader.py
```

New v0.5 tests:

```text
tests/test_safety_metadata.py
tests/test_http_result_utils.py
tests/test_inventory_candidate_builder.py
tests/test_result_schema.py
```

Important assertions:

* Safety metadata defaults to safe values.
* HTTP result utilities convert exceptions to request_error.
* HTTP result utilities reject sensitive headers from summaries.
* HTTP result utilities preserve safe content-type and body-size metadata.
* Inventory candidate builder runs conservative validator.
* Inventory candidate builder does not store sensitive fields.
* Result schema helpers preserve required keys.
* Existing workflow output remains compatible.
* All v0.4 workflow tests continue passing.

---

## Tool Risk Model

Risk levels:

```text
safe
low
medium
high
blocked
unknown
```

### Safe

No external request.

Examples:

```text
tool_check_scope
tool_evaluate_action_risk
tool_summarize_findings
tool_write_report_draft
```

### Low

External request, but limited and non-destructive.

Examples:

```text
tool_safe_http_probe_workflow
tool_safe_security_headers_workflow
tool_safe_cors_observation_workflow
tool_safe_passive_recon_workflow
tool_safe_robots_securitytxt_workflow
tool_safe_sitemap_parser_workflow
```

### Medium

Multiple controlled requests or more sensitive inventory collection.

Examples:

```text
tool_safe_js_endpoint_extraction_workflow
tool_safe_bounded_crawl_workflow
future controlled open redirect observation
future controlled GraphQL observation
```

### High

Requires credentials, account setup, or authorization-sensitive validation.

Examples:

```text
future authz review
future IDOR validation
future authenticated API comparison
```

### Blocked

Never automate.

Examples:

```text
brute force
DoS
mass fuzzing
credential stuffing
destructive actions
unrestricted exploit chains
real data exfiltration
```

### Unknown

Default deny.

Any tool missing from `tool_risk_profiles.json` should be treated as unknown and denied until classified.

---

## v0.5 Acceptance Criteria

v0.5 is complete when:

1. Shared safety metadata helper exists and is tested.
2. Shared HTTP result utility module exists and is tested.
3. Shared inventory candidate builder exists and is tested.
4. Shared result schema helper exists and is tested.
5. At least the v0.4 inventory workflows are refactored to use shared helpers where safe.
6. `server.py` is thinner or MCP wrappers are grouped under `mcp_tools/`.
7. Existing MCP tool names remain stable.
8. Existing request budgets remain unchanged.
9. Existing v0.4 workflow tests pass.
10. New v0.5 helper tests pass.
11. No exploit automation is added.
12. No vulnerability validation is added.
13. No fuzzing, brute force, credential testing, form submission, or state-changing behavior is added.
14. Documentation is updated.
15. v0.6 controlled validation remains future work.

---

## Future v0.6 Direction

Future milestone:

```text
v0.6-controlled-validation
```

Possible v0.6 scope:

```text
controlled_open_redirect_observation
controlled_exposed_file_observation
controlled_graphql_observation
controlled_authz_review_preparation
controlled_idor_validation_preparation
```

v0.6 should use v0.4 inventory and v0.5 standardized helpers as input.

The purpose of v0.6 is controlled validation planning for selected high-value inventory items.

v0.6 is not complete yet.

v0.6 must still use:

* Scope guard
* Risk gate
* Explicit approval
* Request limits
* Evidence rules
* Sensitive-data minimization
* Standard result schema
* Standard safety metadata

---

## Development Rules

For every change:

1. Start from a clean Git state.
2. Create a feature branch.
3. Modify only allowed files.
4. Run relevant tests.
5. Check `git diff`.
6. Commit with a clear message.
7. Merge only after tests pass.

Suggested branch naming:

```text
feature/core-refactor-result-standardization
feature/shared-safety-metadata
feature/http-result-utils
feature/inventory-candidate-builder
feature/mcp-tool-grouping
docs/refactoring-plan
```

Suggested commit style:

```text
Update architecture for v0.5 refactor
Add shared safety metadata helper
Add HTTP result utility helpers
Add inventory candidate builder
Add workflow result schema helpers
Refactor sitemap workflow helpers
Group MCP tool wrappers
Document v0.5 refactor architecture
```
