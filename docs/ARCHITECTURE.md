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
v0.2-risk-gate-and-execution-policy
```

v0.2 completed:

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
* Runtime skill folder structure
* Git version control
* Logging
* Simplified LM Studio toolbox

v0.2 exposed MCP tools:

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
v0.3-runtime-skills-and-skill-loader
```

The next target is to implement the runtime skill knowledge layer.

v0.3 does not add new vulnerability workflows.
v0.3 does not add exploit logic.
v0.3 does not change existing workflow behavior.

The purpose of v0.3 is to let the future runtime AI agent load structured skill knowledge from local Markdown files.

---

## v0.3 Required Files

Required implementation files:

```text
tools/skill_loader.py
tests/test_skill_loader.py
docs/RUNTIME_SKILLS.md
```

Required runtime skill files:

```text
skills/agent_runtime/passive_recon/SKILL.md
skills/agent_runtime/security_headers/SKILL.md
skills/agent_runtime/cors/SKILL.md
skills/agent_runtime/reporting/SKILL.md
skills/agent_runtime/risk_gate/SKILL.md
```

Optional future runtime skill files, not required for v0.3:

```text
skills/agent_runtime/auth_access_control/SKILL.md
skills/agent_runtime/idor/SKILL.md
skills/agent_runtime/open_redirect/SKILL.md
skills/agent_runtime/exposed_files/SKILL.md
skills/agent_runtime/graphql/SKILL.md
```

---

## v0.3 Non-Goals

Do not implement these in v0.3:

```text
safe_js_endpoint_extraction_workflow
safe_robots_securitytxt_workflow
safe_sitemap_parser_workflow
endpoint_inventory_builder
open_redirect workflow
IDOR workflow
auth/access-control workflow
GraphQL workflow
exposed file workflow
exploit automation
fuzzing
bruteforce
credential testing
state-changing validation
```

These belong to later versions.

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
Finding Summarizer
    ↓
Report Writer
```

Current v0.2 flow:

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
Storage
    ↓
Summary / Report
```

v0.3 adds:

```text
Runtime Skill Loader
Runtime SKILL.md knowledge files
Runtime skill documentation
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

Validator Layer
    header_validator
    cors_validator
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
│   └── mcp.log
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── CURRENT_STATE.md
│   ├── FINDING_SCHEMA.md
│   ├── ROADMAP.md
│   ├── TEST_PLAN.md
│   ├── TOOL_RISK_MODEL.md
│   └── RUNTIME_SKILLS.md
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
│   │   └── exposed_files/           # future
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
│   └── skill_loader.py
│
├── validators/
│   ├── __init__.py
│   ├── header_validator.py
│   ├── cors_validator.py
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
│   ├── safe_robots_securitytxt_workflow.py      # future
│   └── safe_js_endpoint_extraction_workflow.py  # future
│
├── tests/
│   ├── test_risk_gate.py
│   ├── test_skill_loader.py
│   ├── test_scope_guard.py             # future
│   ├── test_workflows.py               # future
│   └── test_finding_summarizer.py      # future
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
* Avoid directly executing tools.
* Produce structured plans.

Planner must not bypass:

```text
scope_guard
risk_gate
approval_controller
tool_risk_profiles
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

Current v0.3 runtime skill targets:

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
```

### Required SKILL.md Format

Each runtime `SKILL.md` should include:

```text
# Skill Name

## Purpose

## When to Use

## Preconditions

## Allowed Actions

## Disallowed Actions

## Required Evidence

## Validation Rules

## False Positive Rules

## Escalation Rules

## Output Schema
```

### Runtime Skill Usage

Future planner or runtime agent may use skills to improve decision quality.

Runtime skills should guide:

```text
classification
evidence collection
false-positive reduction
manual validation decision
reporting decision
risk escalation
```

Runtime skills should not directly execute actions.

---

## Skill Loader

Location:

```text
tools/skill_loader.py
```

v0.3 responsibility:

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

Expected successful return shape:

```json
{
  "loaded": true,
  "skill_name": "cors",
  "path": "skills/agent_runtime/cors/SKILL.md",
  "content": "..."
}
```

Expected failure return shape:

```json
{
  "loaded": false,
  "skill_name": "unknown_skill",
  "path": null,
  "content": "",
  "error": "Skill not found."
}
```

Security requirements:

* Skill name must not contain `..`.
* Skill name must not be an absolute path.
* Skill name must not contain path separators that escape the skill directory.
* Loader must resolve paths safely under `skills/agent_runtime`.
* Loader must return text only.
* Loader must never execute skill content.

---

## Codex Development Skill Layer

Location:

```text
skills/codex_dev/
```

Purpose:

Codex development skills help maintain the project.

They define:

* How to add a workflow
* How to write tests
* How to maintain architecture
* How to update documentation
* How to keep `server.py` thin

Codex skills are not used by the runtime penetration testing agent.

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

Workflow responsibilities:

* Check scope.
* Stop if out of scope.
* Call low-level tools.
* Call validators.
* Save findings.
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
```

v0.3 planned tool:

```text
skill_loader.py
```

Rules:

* Tools should be single-purpose.
* Tools should not contain business workflow logic.
* External-request tools should be called from workflows.
* Tools should return structured dictionaries.
* Tools should avoid storing sensitive content.
* Tools that only read local files must still fail safely.

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
    "should_report": False,
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

### `scope.json`

Source of truth for authorized targets.

All external workflows must respect it.

### `scan_policy.json`

Global scan policy.

Should define:

```json
{
  "default_scan_level": "low-risk",
  "allow_fuzzing": false,
  "allow_bruteforce": false,
  "allow_exploitation": false,
  "allow_crawling": false,
  "save_sensitive_data": false,
  "require_scope_check": true
}
```

### `false_positive_rules.json`

False positive rule source.

If no rules exist yet, use:

```json
[]
```

### `tool_risk_profiles.json`

Source of truth for tool risk classification.

Any exposed MCP tool must have a profile here.

Unknown tools must be denied by default.

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
mcp.log
```

Rules:

* Runtime data must not be committed.
* Only `data/.gitkeep` should be committed.
* Findings should not include secrets, cookies, tokens, personal data, payment data, or sensitive response bodies.
* Evidence should favor metadata, hashes, body size, status code, headers summary, and reproduction metadata.

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

### Candidate Finding

Potential issue requiring manual validation.

Example:

* Missing CSP and X-Frame-Options on an interactive frontend
* Reflected CORS origin with credentials
* Potential exposed file

### Needs Manual Validation

Evidence is insufficient or requires controlled approval.

Example:

* CORS with credentials requires authorized test account
* Authz/IDOR requires controlled account pair

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
```

### Medium

More targeted validation or multiple controlled requests.

Examples:

```text
future JS endpoint extraction
future robots/security.txt/sitemap workflow
future exposed file observation
future open redirect observation
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

## v0.3 Implementation Plan

The next implementation target is:

```text
Runtime Skills and Skill Loader
```

Step 1:

```text
tools/skill_loader.py
tests/test_skill_loader.py
```

Step 2:

```text
skills/agent_runtime/passive_recon/SKILL.md
skills/agent_runtime/security_headers/SKILL.md
skills/agent_runtime/cors/SKILL.md
skills/agent_runtime/reporting/SKILL.md
skills/agent_runtime/risk_gate/SKILL.md
```

Step 3:

```text
docs/RUNTIME_SKILLS.md
docs/CURRENT_STATE.md
```

---

## v0.3 Acceptance Criteria

v0.3 is complete when:

1. `tools/skill_loader.py` can safely load `skills/agent_runtime/<skill_name>/SKILL.md`.
2. `skill_loader.py` rejects path traversal.
3. `skill_loader.py` rejects absolute paths.
4. `skill_loader.py` does not execute skill content.
5. `skill_loader.py` does not call workflows.
6. `skill_loader.py` does not send HTTP requests.
7. `tests/test_skill_loader.py` passes.
8. Runtime `SKILL.md` files exist for:

   * passive_recon
   * security_headers
   * cors
   * reporting
   * risk_gate
9. Runtime skill files follow the standard format.
10. `docs/RUNTIME_SKILLS.md` explains runtime skills and their boundaries.
11. Existing `tests/test_risk_gate.py` still passes.
12. No new vulnerability workflow is added.
13. No existing workflow behavior is changed.
14. `server.py` remains unchanged unless explicitly requested later.

---

## Future v0.4 Direction

Future milestone:

```text
v0.4-attack-surface-inventory
```

Possible v0.4 scope:

```text
safe_robots_securitytxt_workflow
safe_sitemap_parser_workflow
safe_js_endpoint_extraction_workflow
endpoint_inventory_builder
```

v0.4 should still follow:

```text
scope guard
risk gate
approval controller
tool risk profiles
workflow safety metadata
no sensitive data storage
```

---

## Testing Strategy

Minimum current tests:

```text
tests/test_risk_gate.py
```

v0.3 adds:

```text
tests/test_skill_loader.py
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
* Existing workflow behavior should not change when adding skill loader.

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
feature/runtime-skills
docs/update-architecture-v03
test/skill-loader
```

Suggested commit style:

```text
Update architecture for v0.3 runtime skills
Add runtime skill loader
Add runtime agent skill definitions
Document runtime skills architecture
```
