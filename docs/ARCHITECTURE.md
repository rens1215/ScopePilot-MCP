# Architecture

## Project Name

```text
MCP_SERVER_FOR_LLM_HACKER
```

## System Goal

This project is an AI-assisted authorized web penetration testing platform built around MCP tools.

The system is designed to help an AI agent perform scoped reconnaissance, controlled validation, evidence collection, finding prioritization, finding summarization, and reproducible report generation.

The system must operate only on explicitly authorized in-scope targets.

This project is not an unrestricted attack automation tool. Every external action must pass scope validation, risk policy, workflow safety rules, and approval rules where required.

---

## Current Stable Version

Current stable version:

```text
v0.3-runtime-skills-and-skill-loader
```

Completed through v0.3:

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
tool_summarize_findings
tool_write_report_draft
```

---

## Next Architecture Target

Next milestone:

```text
v0.4-attack-surface-inventory
```

The purpose of v0.4 is to build an attack surface inventory layer.

This layer helps the future AI agent understand:

* What public entry points exist.
* Which endpoints are more valuable.
* Which endpoints are likely frontend pages, APIs, auth pages, static assets, admin surfaces, or documentation.
* Which endpoints should be prioritized for later controlled validation.
* Which endpoints are likely low-value and should not waste request budget.

v0.4 does not perform exploitation.

v0.4 does not perform fuzzing, brute force, credential testing, destructive validation, or state-changing validation.

v0.4 builds a safe target map for later versions.

---

## Why v0.4 Exists

Without an attack surface inventory, the AI agent may test blindly.

Blind testing causes:

* Low signal-to-noise ratio.
* More false positives.
* Wasted request budget.
* Poor prioritization.
* Unstable tool selection.
* Weak exploit-chain reasoning.

Attack surface inventory gives the AI agent a structured map before deeper validation.

The goal is not to prove vulnerabilities yet.

The goal is to identify high-value areas such as:

* Login pages
* Account pages
* User profile endpoints
* API endpoints
* Upload endpoints
* OAuth / callback endpoints
* Admin-looking paths
* GraphQL endpoints
* Public documentation
* JavaScript-discovered routes
* Sitemap-discovered routes
* Robots/security.txt/sitemap metadata

---

## v0.4 Scope

v0.4 should add safe inventory capabilities only.

Recommended v0.4 modules:

```text
workflows/safe_robots_securitytxt_workflow.py
workflows/safe_sitemap_parser_workflow.py
workflows/safe_js_endpoint_extraction_workflow.py
tools/endpoint_inventory.py
tools/url_normalizer.py
tools/js_endpoint_extractor.py
validators/inventory_validator.py
tests/test_attack_surface_inventory.py
docs/ATTACK_SURFACE_INVENTORY.md
```

Not every file must be implemented at once. v0.4 should be built in small steps.

Recommended implementation order:

```text
Step 1: URL normalization and inventory data model
Step 2: robots.txt / security.txt / sitemap observation workflow
Step 3: sitemap parser
Step 4: safe JS endpoint extraction
Step 5: endpoint inventory builder
Step 6: documentation and tests
```

---

## v0.4 Non-Goals

Do not implement these in v0.4:

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
```

These belong to later controlled-validation phases, and only after risk gate, explicit approval, request limits, and evidence rules are in place.

---

## High-Level Execution Flow

Long-term intended flow:

```text
User Request
    ↓
Agent Planner
    ↓
Runtime Skill Loader
    ↓
Risk Gate
    ↓
Approval Controller
    ↓
MCP Tool Wrapper
    ↓
Workflow
    ↓
Low-level Tool
    ↓
Validator
    ↓
Finding Storage
    ↓
Endpoint Inventory
    ↓
Finding Summarizer
    ↓
Report Writer
```

Current v0.3 flow:

```text
User Request
    ↓
MCP Tool Wrapper
    ↓
Runtime Skill Loader
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
Storage
    ↓
Summary / Report
```

v0.4 adds:

```text
Attack Surface Inventory
Endpoint Inventory Builder
Safe robots/security.txt/sitemap observation
Safe JS endpoint extraction
Endpoint prioritization
```

---

## Layered Architecture

```text
MCP Layer
    server.py

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
    future safe_robots_securitytxt_workflow
    future safe_sitemap_parser_workflow
    future safe_js_endpoint_extraction_workflow

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
    future endpoint_inventory
    future url_normalizer
    future js_endpoint_extractor

Validator Layer
    header_validator
    cors_validator
    future inventory_validator
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
│   ├── FINDING_SCHEMA.md
│   ├── ROADMAP.md
│   ├── TEST_PLAN.md
│   ├── TOOL_RISK_MODEL.md
│   ├── RUNTIME_SKILLS.md
│   └── ATTACK_SURFACE_INVENTORY.md
│
├── skills/
│   ├── agent_runtime/
│   │   ├── passive_recon/
│   │   │   └── SKILL.md
│   │   ├── security_headers/
│   │   │   └── SKILL.md
│   │   ├── cors/
│   │   │   └── SKILL.md
│   │   ├── reporting/
│   │   │   └── SKILL.md
│   │   ├── risk_gate/
│   │   │   └── SKILL.md
│   │   ├── auth_access_control/     # future
│   │   │   └── SKILL.md
│   │   ├── idor/                    # future
│   │   │   └── SKILL.md
│   │   ├── open_redirect/           # future
│   │   │   └── SKILL.md
│   │   ├── exposed_files/           # future
│   │   │   └── SKILL.md
│   │   └── graphql/                 # future
│   │       └── SKILL.md
│   │
│   └── codex_dev/
│       ├── project_maintenance/
│       │   └── SKILL.md
│       ├── workflow_development/
│       │   └── SKILL.md
│       └── testing/
│           └── SKILL.md
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
│   ├── endpoint_inventory.py        # v0.4
│   ├── url_normalizer.py            # v0.4
│   └── js_endpoint_extractor.py     # v0.4
│
├── validators/
│   ├── __init__.py
│   ├── header_validator.py
│   ├── cors_validator.py
│   ├── inventory_validator.py       # v0.4
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
│   ├── safe_robots_securitytxt_workflow.py      # v0.4
│   ├── safe_sitemap_parser_workflow.py          # v0.4
│   └── safe_js_endpoint_extraction_workflow.py  # v0.4
│
├── tests/
│   ├── test_risk_gate.py
│   ├── test_skill_loader.py
│   ├── test_attack_surface_inventory.py   # v0.4
│   ├── test_url_normalizer.py             # v0.4
│   ├── test_js_endpoint_extractor.py      # v0.4
│   ├── test_scope_guard.py                # future
│   ├── test_workflows.py                  # future
│   └── test_finding_summarizer.py         # future
│
├── server.py
├── requirements.txt
├── README.md
└── AGENTS.md
```

Some files listed above are future targets and may not exist yet.

---

## MCP Layer

Location:

```text
server.py
```

Purpose:

* Register MCP tools.
* Expose controlled workflows to LM Studio.
* Keep a stable interface between the local LLM and Python execution logic.

Rules:

* `server.py` should only contain MCP wrappers.
* `server.py` should not contain workflow implementation details.
* `server.py` should not send raw HTTP requests.
* `server.py` should not make validator decisions.
* New MCP tools should be added only when necessary.
* Low-level tools should generally remain hidden from LM Studio.
* Every exposed MCP tool must have a profile in `config/tool_risk_profiles.json`.

Current exposed MCP tools:

```text
tool_check_scope
tool_evaluate_action_risk
tool_safe_http_probe_workflow
tool_safe_security_headers_workflow
tool_safe_cors_observation_workflow
tool_safe_passive_recon_workflow
tool_summarize_findings
tool_write_report_draft
```

Possible v0.4 exposed tools:

```text
tool_safe_robots_securitytxt_workflow
tool_safe_sitemap_parser_workflow
tool_safe_js_endpoint_extraction_workflow
tool_summarize_endpoint_inventory
```

Only expose these after:

* workflow is implemented
* tests pass
* risk profile exists
* documentation is updated
* LM Studio behavior is checked

---

## Agent Layer

Location:

```text
agent/
```

Purpose:

The Agent Layer controls whether and how an action should be executed.

Current modules:

```text
risk_gate.py
approval_controller.py
```

Future modules:

```text
planner.py
execution_state.py
task_router.py
```

### `risk_gate.py`

Current responsibility:

* Evaluate tool risk.
* Check if a tool is allowed in the current execution mode.
* Require approval for low, medium, and high risk actions.
* Deny unknown or blocked tools by default.
* Fail closed when tool risk profile is missing or malformed.

Rules:

* Must not execute tools.
* Must not call workflows.
* Must not send HTTP requests.
* Must not modify target state.
* Must not bypass scope guard.

### `approval_controller.py`

Current responsibility:

* Build approval request objects.
* Explain estimated requests, risk level, state-change risk, credential usage, and allowed modes.
* Prepare data that the UI or LLM can show before execution.

Rules:

* Must not execute tools.
* Must not call workflows.
* Must not send HTTP requests.
* Must not decide new policy.
* Allow/deny decision must come from `risk_gate.py`.

### Future `planner.py`

Future responsibility:

* Convert user intent into an execution plan.
* Select appropriate workflows.
* Load runtime skills when needed.
* Use endpoint inventory to prioritize later controlled validation.
* Avoid directly executing tools.
* Produce structured plans.

Planner must not bypass:

```text
scope_guard
risk_gate
approval_controller
tool_risk_profiles
runtime skill rules
```

---

## Runtime Skill Layer

Location:

```text
skills/agent_runtime/
```

Purpose:

Runtime skills are local Markdown knowledge files for the future autonomous security testing AI agent.

They define:

* When to use a skill
* Preconditions
* Allowed actions
* Disallowed actions
* Evidence requirements
* Validation rules
* False-positive rules
* Escalation rules
* Output schemas

Runtime skills are not executable code.

Runtime skills must not contain:

```text
unrestricted payload lists
brute-force instructions
credential attack instructions
destructive procedures
real data exfiltration instructions
unrestricted exploit chaining
```

Current runtime skill targets:

```text
passive_recon
security_headers
cors
reporting
risk_gate
```

Future runtime skill targets:

```text
auth_access_control
idor
open_redirect
exposed_files
graphql
attack_surface_inventory
```

---

## Skill Loader

Location:

```text
tools/skill_loader.py
```

Current responsibility:

* Load local Markdown skill files from `skills/agent_runtime/<skill_name>/SKILL.md`.
* Return skill content as text.
* Return safe structured metadata.
* Fail safely when the skill does not exist.
* Reject path traversal attempts.
* Reject absolute paths.
* Reject unsafe skill names.

The skill loader must not:

```text
execute SKILL.md content
execute Python code
call MCP tools
call workflows
send HTTP requests
modify findings
modify config
modify logs
modify target state
```

---

## Attack Surface Inventory Layer

v0.4 introduces the Attack Surface Inventory Layer.

Purpose:

* Collect safe public entry-point metadata.
* Normalize discovered URLs.
* Classify endpoint types.
* De-duplicate repeated endpoints.
* Track discovery source.
* Assign review priority.
* Store non-sensitive endpoint metadata.
* Provide later planner input.

The inventory layer should answer:

```text
What endpoints exist?
Where did each endpoint come from?
What type of endpoint is it?
How valuable is it for later validation?
What skill might be relevant next?
What safety constraints apply?
```

The inventory layer must not:

```text
exploit endpoints
brute force paths
crawl without limits
perform mass fuzzing
use credentials
change target state
save sensitive response bodies
exfiltrate data
```

---

## Endpoint Inventory Data Model

A stored inventory item should try to follow:

```json
{
  "target": "",
  "url": "",
  "normalized_url": "",
  "source": "robots | security_txt | sitemap | html_script_tag | javascript_static_analysis | manual",
  "method_guess": "GET",
  "endpoint_type": "frontend | api | auth_page | admin_candidate | static_asset | documentation | unknown",
  "priority": "low | medium | high",
  "confidence": "low | medium | high",
  "discovered_by": "",
  "evidence": {
    "status_code": null,
    "content_type": "",
    "body_size": null,
    "headers_summary": {}
  },
  "safety": {
    "requests_sent": 0,
    "fuzzing": false,
    "bruteforce": false,
    "exploitation": false,
    "crawling": false,
    "credentialed_request": false
  },
  "recommended_next_skill": "",
  "recommended_next_steps": [],
  "notes": ""
}
```

Inventory items should be saved without sensitive data.

---

## v0.4 Safe Workflows

### `safe_robots_securitytxt_workflow.py`

Purpose:

* Fetch public metadata files from an in-scope target.
* Observe:

  * `/robots.txt`
  * `/.well-known/security.txt`
  * `/sitemap.xml`

Rules:

* Must check scope first.
* Must use low request limits.
* Must not follow arbitrary links automatically.
* Must not scan every path from robots.txt.
* Must not treat disallowed paths as permission to scan.
* Must save only non-sensitive metadata and discovered public references.

### `safe_sitemap_parser_workflow.py`

Purpose:

* Parse sitemap XML from an in-scope target.
* Extract URLs.
* Normalize URLs.
* Store public endpoint inventory items.

Rules:

* Must check scope first.
* Must limit sitemap size.
* Must limit URL count.
* Must not recursively crawl unlimited sitemap indexes.
* Must not request every discovered URL unless explicitly designed and approved.
* Must only store endpoint metadata.

### `safe_js_endpoint_extraction_workflow.py`

Purpose:

* Analyze directly referenced JavaScript files from an in-scope frontend page.
* Extract likely endpoint strings and route patterns.
* Add endpoint candidates to inventory.

Rules:

* Must check scope first.
* Must limit number of JS files.
* Must limit file size.
* Must not execute JavaScript.
* Must not evaluate JavaScript.
* Must not crawl arbitrary discovered endpoints.
* Must not store secrets if accidentally found.
* Must store only safe metadata, hashes, and endpoint candidates.

---

## v0.4 Tools

### `url_normalizer.py`

Purpose:

* Normalize discovered URLs.
* Remove fragments.
* Normalize scheme/host casing.
* Resolve relative paths safely.
* Filter out unsupported schemes.
* Help de-duplicate inventory items.

Must not send requests.

### `endpoint_inventory.py`

Purpose:

* Build inventory item objects.
* De-duplicate by normalized URL and source.
* Save inventory items to local data file.
* Summarize inventory by target, source, endpoint type, and priority.

Must not send requests.

### `js_endpoint_extractor.py`

Purpose:

* Extract likely endpoint strings from JavaScript text.
* Identify route-like strings, API-like paths, and URL-like tokens.
* Return candidate endpoints.

Must not execute JavaScript.

Must not evaluate JavaScript.

Must not send requests.

---

## v0.4 Validators

### `inventory_validator.py`

Purpose:

* Validate endpoint inventory item shape.
* Classify endpoint type conservatively.
* Reduce noisy candidates.
* Assign priority and confidence.
* Recommend next skill.

Must not send requests.

Must not execute payloads.

Must not claim vulnerability impact.

---

## Workflow Layer

Location:

```text
workflows/
```

Purpose:

Workflows are controlled multi-step procedures.

Current workflows:

```text
safe_http_probe_workflow.py
safe_security_headers_workflow.py
safe_cors_observation_workflow.py
safe_passive_recon_workflow.py
```

v0.4 candidate workflows:

```text
safe_robots_securitytxt_workflow.py
safe_sitemap_parser_workflow.py
safe_js_endpoint_extraction_workflow.py
```

Workflow responsibilities:

* Check scope.
* Stop if out of scope.
* Check risk profile where applicable.
* Call low-level tools.
* Call validators.
* Save findings or inventory.
* Return safety metadata.
* Log key events.

Every external workflow must return:

```json
{
  "safety": {
    "requests_sent": 0,
    "scan_level": "low-risk",
    "fuzzing": false,
    "bruteforce": false,
    "exploitation": false,
    "crawling": false,
    "credentialed_request": false
  }
}
```

Workflow rules:

* No workflow may skip scope checking.
* No workflow may store sensitive data.
* No workflow may perform unrestricted exploit chaining.
* No workflow may perform brute force, DoS, credential stuffing, or mass fuzzing.
* Workflows should be deterministic and testable.
* Medium/high risk validation must go through `risk_gate` and explicit approval.

---

## Tool Layer

Location:

```text
tools/
```

Purpose:

Tools are reusable low-level utilities.

Current tools:

```text
scope_guard.py
http_probe.py
security_headers.py
endpoint_classifier.py
priority_scorer.py
finding_summarizer.py
storage.py
logger.py
report_writer.py
policy_loader.py
skill_loader.py
```

v0.4 candidate tools:

```text
url_normalizer.py
endpoint_inventory.py
js_endpoint_extractor.py
```

Rules:

* Tools should be single-purpose.
* Tools should not contain business workflow logic.
* External-request tools should be called from workflows.
* Tools should return structured dictionaries.
* Tools should avoid storing sensitive content.
* Tools that only parse local text must not send requests.
* Tools that parse JavaScript must not execute JavaScript.

---

## Validator Layer

Location:

```text
validators/
```

Purpose:

Validators classify raw observations and reduce false positives.

Current validators:

```text
header_validator.py
cors_validator.py
```

v0.4 candidate validator:

```text
inventory_validator.py
```

Future validators:

```text
exposed_file_validator.py
open_redirect_validator.py
authz_validator.py
idor_validator.py
```

Validators must return:

```python
{
    "status": "observation | candidate_finding | confirmed_finding | needs_manual_validation",
    "severity": "info | low | medium | high | critical",
    "confidence": "low | medium | high",
    "should_report": false,
    "reason": "...",
    "false_positive_notes": []
}
```

Validator rules:

* Validators must not send network requests.
* Validators must not save findings.
* Validators must not perform exploitation.
* Validators must not claim confirmed impact without evidence.
* Validators should be conservative.

---

## Config Layer

Location:

```text
config/
```

Purpose:

Configuration controls scope, policy, false positive behavior, and tool risk.

Important files:

```text
scope.json
scan_policy.json
false_positive_rules.json
tool_risk_profiles.json
```

Any new exposed MCP tool must have a profile in:

```text
config/tool_risk_profiles.json
```

Unknown tools must be denied by default.

v0.4 candidate tools should be added to risk profiles only when they are implemented and exposed.

---

## Data Layer

Location:

```text
data/
```

Runtime data:

```text
findings.jsonl
evidence.jsonl
endpoint_inventory.jsonl
mcp.log
```

Rules:

* Runtime data must not be committed.
* Only `data/.gitkeep` should be committed.
* Findings and inventory should not include secrets, cookies, tokens, personal data, payment data, or sensitive response bodies.
* Evidence should favor metadata, hashes, body size, status code, headers summary, normalized URLs, and discovery source.

---

## Report Layer

Current location:

```text
tools/report_writer.py
```

Future location:

```text
report/
```

Purpose:

* Generate reproducible report drafts.
* Convert validated findings into structured reports.
* Include evidence summary.
* Include reproduction steps.
* Include remediation.
* Include false-positive notes.
* Avoid storing sensitive data.

Future files:

```text
report/report_writer.py
report/report_schema.py
report/templates/
```

---

## Finding Lifecycle

A finding should move through these states:

```text
observation
    ↓
candidate_finding
    ↓
needs_manual_validation
    ↓
confirmed_finding
    ↓
report_draft
```

Definitions:

### Observation

A raw or lightly interpreted result.

Example:

* HTTP 200 response
* Missing security headers
* No CORS headers
* Frontend endpoint classification
* Public endpoint discovered from sitemap

### Candidate Finding

Potential issue requiring manual validation.

Example:

* Missing CSP and X-Frame-Options on an interactive frontend
* Reflected CORS origin with credentials
* Sensitive-looking endpoint candidate
* Potential exposed file reference

### Needs Manual Validation

Evidence is insufficient or requires controlled approval.

Example:

* CORS with credentials requires authorized test account
* Authz/IDOR requires controlled account pair
* Admin-looking endpoint requires authorized validation

### Confirmed Finding

A reproducible issue with clear impact, validated within scope and policy.

### Report Draft

A structured report generated from confirmed or manually validated evidence.

---

## Finding Schema

Every saved finding should try to include:

```json
{
  "type": "observation",
  "title": "",
  "target": "",
  "category": "",
  "vulnerability_category": "",
  "endpoint_classification": {
    "classification": "",
    "confidence": "",
    "reason": ""
  },
  "severity": "info",
  "confidence": "medium",
  "status": "observation",
  "priority": {
    "priority": "low",
    "score": 0,
    "reasons": []
  },
  "evidence_summary": "",
  "validator_result": {
    "status": "",
    "severity": "",
    "confidence": "",
    "should_report": false,
    "reason": "",
    "false_positive_notes": []
  },
  "next_step": "",
  "safety": {
    "requests_sent": 0,
    "fuzzing": false,
    "bruteforce": false,
    "exploitation": false,
    "crawling": false,
    "credentialed_request": false
  }
}
```

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
future tool_safe_robots_securitytxt_workflow
future tool_safe_sitemap_parser_workflow
future tool_safe_js_endpoint_extraction_workflow
```

### Medium

More targeted validation or multiple controlled requests.

Examples:

```text
future exposed file observation
future open redirect observation
future GraphQL observation
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

## v0.4 Implementation Plan

The next implementation target is:

```text
Attack Surface Inventory
```

Recommended implementation order:

### Step 1: Inventory foundation

```text
tools/url_normalizer.py
tools/endpoint_inventory.py
validators/inventory_validator.py
tests/test_attack_surface_inventory.py
docs/ATTACK_SURFACE_INVENTORY.md
```

### Step 2: Public metadata workflow

```text
workflows/safe_robots_securitytxt_workflow.py
config/tool_risk_profiles.json
server.py wrapper only after tests pass
```

### Step 3: Sitemap workflow

```text
workflows/safe_sitemap_parser_workflow.py
config/tool_risk_profiles.json
server.py wrapper only after tests pass
```

### Step 4: JS endpoint extraction workflow

```text
tools/js_endpoint_extractor.py
workflows/safe_js_endpoint_extraction_workflow.py
config/tool_risk_profiles.json
server.py wrapper only after tests pass
```

### Step 5: Inventory summary

```text
tool_summarize_endpoint_inventory
docs/ATTACK_SURFACE_INVENTORY.md update
```

Do not implement all steps at once.

---

## v0.4 Acceptance Criteria

v0.4 is complete when:

1. Inventory items can be created with a stable schema.
2. URLs can be normalized safely.
3. Duplicate endpoints can be de-duplicated.
4. Public metadata endpoints can be observed safely.
5. Sitemap URLs can be parsed with size and count limits.
6. JavaScript endpoint candidates can be extracted without executing JavaScript.
7. Inventory items are saved without sensitive data.
8. Inventory summary can group endpoints by target, source, endpoint type, and priority.
9. New exposed MCP tools have risk profiles.
10. New workflows check scope first.
11. New workflows return safety metadata.
12. Tests pass.
13. Existing `tests/test_risk_gate.py` and `tests/test_skill_loader.py` still pass.
14. No exploit automation is added.
15. No brute force, DoS, mass fuzzing, credential testing, or destructive action is added.

---

## Future v0.5 Direction

Future milestone:

```text
v0.5-controlled-validation
```

Possible v0.5 scope:

```text
controlled_open_redirect_observation
controlled_exposed_file_observation
controlled_graphql_observation
controlled_authz_review_preparation
controlled_idor_validation_preparation
```

v0.5 should use the v0.4 inventory as input.

The purpose of v0.5 is to validate selected high-value inventory items under strict risk gate, approval, and evidence rules.

---

## Testing Strategy

Minimum current tests:

```text
tests/test_risk_gate.py
tests/test_skill_loader.py
```

v0.4 adds:

```text
tests/test_attack_surface_inventory.py
tests/test_url_normalizer.py
tests/test_js_endpoint_extractor.py
```

Future tests:

```text
tests/test_scope_guard.py
tests/test_workflows.py
tests/test_finding_summarizer.py
```

Important assertions:

* Risk gate should deny unknown tools.
* Risk gate should deny blocked tools.
* Risk gate should require approval for low-risk external workflows.
* Skill loader should load valid local runtime skills.
* Skill loader should reject missing skills safely.
* Skill loader should reject path traversal.
* Skill loader should reject absolute paths.
* Skill loader should not execute skill content.
* URL normalizer should remove fragments.
* URL normalizer should reject unsupported schemes.
* Endpoint inventory should de-duplicate normalized URLs.
* JS extractor should not execute JavaScript.
* Existing workflow behavior should not change when adding inventory tools.

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
feature/attack-surface-inventory
feature/robots-securitytxt-workflow
feature/js-endpoint-extraction
test/endpoint-inventory
docs/attack-surface-inventory
```

Suggested commit style:

```text
Update architecture for v0.4 attack surface inventory
Add endpoint inventory foundation
Add safe robots securitytxt workflow
Add safe sitemap parser workflow
Add safe JS endpoint extraction workflow
Document attack surface inventory architecture
```
