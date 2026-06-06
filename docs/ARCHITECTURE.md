# Architecture

## Project Name

```text
MCP_SERVER_FOR_LLM_HACKER
```

## System Goal

This project is an AI-assisted authorized web penetration testing platform built around MCP tools.

The system is designed to help an AI agent perform scoped reconnaissance, controlled validation, evidence collection, finding prioritization, finding summarization, and reproducible report generation.

The system must operate only on explicitly authorized in-scope targets.

---

## Current Status

Current stable version:

```text
v0.1-safe-passive-recon
```

Implemented:

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
* Runtime skill folder structure
* Basic Git version control
* Logging
* Simplified LM Studio toolbox

Not implemented yet:

* Agent planner
* Risk gate
* Approval controller
* Execution state
* Task router
* Evidence store
* Tool risk profiles
* Runtime skill loader
* JS endpoint extraction workflow
* Robots/security.txt/sitemap workflow
* Controlled validation workflows

---

## Next Architecture Target

Next milestone:

```text
v0.2-risk-gate-and-execution-policy
```

The next target is to implement the risk control layer.

Required files:

```text
agent/__init__.py
agent/risk_gate.py
agent/approval_controller.py
tools/policy_loader.py
config/tool_risk_profiles.json
tests/test_risk_gate.py
docs/TOOL_RISK_MODEL.md
```

Optional after tests pass:

```text
server.py wrapper: tool_evaluate_action_risk
```

Do not add new vulnerability workflows before the risk gate is complete.

---

## High-Level Execution Flow

The intended long-term execution flow is:

```text
User Request
    ↓
Agent Planner
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

Current v0.1 flow is simpler:

```text
User Request
    ↓
MCP Tool Wrapper
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

v0.2 adds:

```text
Risk Gate
Approval Controller
Tool Risk Profiles
```

---

## Layered Architecture

```text
MCP Layer
    server.py

Agent Layer
    planner
    risk_gate
    approval_controller
    execution_state
    task_router

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
    report templates
```

---

## Directory Structure

Recommended structure:

```text
MCP_SERVER_FOR_LLM_HACKER/
├── agent/
│   ├── __init__.py
│   ├── planner.py
│   ├── risk_gate.py
│   ├── approval_controller.py
│   ├── execution_state.py
│   └── task_router.py
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
│   ├── FINDING_SCHEMA.md
│   ├── ROADMAP.md
│   ├── TEST_PLAN.md
│   └── TOOL_RISK_MODEL.md
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
│   │   └── risk_gate/
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
│   └── policy_loader.py
│
├── validators/
│   ├── __init__.py
│   ├── header_validator.py
│   ├── cors_validator.py
│   ├── exposed_file_validator.py
│   ├── open_redirect_validator.py
│   └── authz_validator.py
│
├── workflows/
│   ├── __init__.py
│   ├── safe_http_probe_workflow.py
│   ├── safe_security_headers_workflow.py
│   ├── safe_cors_observation_workflow.py
│   ├── safe_passive_recon_workflow.py
│   ├── safe_robots_securitytxt_workflow.py
│   └── safe_js_endpoint_extraction_workflow.py
│
├── tests/
│   ├── test_scope_guard.py
│   ├── test_workflows.py
│   ├── test_risk_gate.py
│   └── test_finding_summarizer.py
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

Example wrapper style:

```python
@mcp.tool()
def tool_safe_passive_recon_workflow(target: str) -> dict:
    return safe_passive_recon_workflow(target)
```

---

## Agent Layer

Location:

```text
agent/
```

Purpose:

The Agent Layer controls whether and how an action should be executed.

Planned modules:

```text
planner.py
risk_gate.py
approval_controller.py
execution_state.py
task_router.py
```

### `planner.py`

Future responsibility:

* Convert user intent into an execution plan.
* Select appropriate workflows.
* Avoid directly executing tools.
* Produce structured plans.

Example future plan:

```json
{
  "target": "example.com",
  "goal": "authorized_web_pentest",
  "steps": [
    {
      "step_id": "scope-check",
      "tool": "tool_check_scope",
      "risk_level": "safe",
      "requires_approval": false
    },
    {
      "step_id": "passive-recon",
      "tool": "tool_safe_passive_recon_workflow",
      "risk_level": "low",
      "requires_approval": true
    }
  ]
}
```

### `risk_gate.py`

v0.2 responsibility:

* Evaluate tool risk.
* Check if a tool is allowed in the current mode.
* Require approval for low, medium, and high risk actions.
* Deny unknown or blocked tools by default.

### `approval_controller.py`

v0.2 responsibility:

* Build approval request objects.
* Explain estimated requests, risk level, state change risk, and credential usage.
* Prepare data that the UI or LLM can show before execution.

### `execution_state.py`

Future responsibility:

* Track current target.
* Track completed steps.
* Track approvals.
* Track request budget.
* Track workflow state.

### `task_router.py`

Future responsibility:

* Route approved plan steps to the proper MCP workflow.
* Prevent the LLM from directly selecting unsafe actions.

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
```

Planned tools:

```text
policy_loader.py
skill_loader.py
evidence_store.py
```

Rules:

* Tools should be single-purpose.
* Tools should not contain business workflow logic.
* External-request tools should be called from workflows.
* Tools should return structured dictionaries.
* Tools should avoid storing sensitive content.

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

## Skill Layer

Location:

```text
skills/
```

There are two skill categories:

```text
skills/agent_runtime/
skills/codex_dev/
```

### Runtime Skills

Location:

```text
skills/agent_runtime/
```

Purpose:

Runtime skills are for the future autonomous security testing AI agent.

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

Runtime skills must not contain unrestricted attack payload lists, brute-force instructions, credential attacks, or destructive procedures.

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
```

### Codex Development Skills

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

v0.2 source of truth for tool risk classification.

Example:

```json
{
  "tool_safe_passive_recon_workflow": {
    "risk_level": "low",
    "external_requests": true,
    "default_requires_approval": true,
    "max_requests": 3,
    "changes_state": false,
    "uses_credentials": false,
    "allowed_modes": ["authorized", "lab"]
  }
}
```

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

* `tool_check_scope`
* `tool_summarize_findings`
* `tool_write_report_draft`
* future `tool_evaluate_action_risk`

### Low

External request, but limited and non-destructive.

Examples:

* `tool_safe_http_probe_workflow`
* `tool_safe_security_headers_workflow`
* `tool_safe_cors_observation_workflow`
* `tool_safe_passive_recon_workflow`

### Medium

More targeted validation or multiple controlled requests.

Examples:

* Future JS endpoint extraction
* Future robots/security.txt/sitemap workflow
* Future exposed file observation
* Future open redirect observation

### High

Requires credentials, account setup, or authorization-sensitive validation.

Examples:

* Future authz review
* Future IDOR validation
* Future authenticated API comparison

### Blocked

Never automate.

Examples:

* Brute force
* DoS
* Mass fuzzing
* Credential stuffing
* Destructive actions
* Unrestricted exploit chains
* Real data exfiltration

### Unknown

Default deny.

Any tool missing from `tool_risk_profiles.json` should be treated as unknown and denied until classified.

---

## v0.2 Implementation Plan

The next implementation target is:

```text
Risk Gate and Execution Policy
```

Add:

```text
agent/__init__.py
agent/risk_gate.py
agent/approval_controller.py
tools/policy_loader.py
config/tool_risk_profiles.json
tests/test_risk_gate.py
docs/TOOL_RISK_MODEL.md
```

Optional after tests pass:

```text
tool_evaluate_action_risk
```

in:

```text
server.py
```

---

## v0.2 Acceptance Criteria

v0.2 is complete when:

1. `risk_gate.py` can classify tool actions as `safe`, `low`, `medium`, `high`, `blocked`, or `unknown`.
2. Unknown tools are denied by default.
3. Blocked tools are denied.
4. Low, medium, and high risk tools require approval unless explicitly configured otherwise.
5. `tool_risk_profiles.json` contains profiles for all exposed MCP tools.
6. `approval_controller.py` can build approval request objects.
7. `tests/test_risk_gate.py` passes.
8. Existing workflow tests still pass.
9. No existing workflow behavior is changed.
10. No new vulnerability workflow is added in v0.2.
11. `server.py` remains thin.

---

## Current Exposed MCP Tools

Recommended current exposed MCP tools:

```text
tool_check_scope
tool_safe_http_probe_workflow
tool_safe_security_headers_workflow
tool_safe_cors_observation_workflow
tool_safe_passive_recon_workflow
tool_summarize_findings
tool_write_report_draft
```

Optional after v0.2:

```text
tool_evaluate_action_risk
```

Low-level tools should generally remain hidden from LM Studio.

---

## Testing Strategy

Minimum tests:

```text
tests/test_scope_guard.py
tests/test_workflows.py
tests/test_risk_gate.py
tests/test_finding_summarizer.py
```

Important assertions:

* `example.com` should be in scope for local testing.
* `google.com` should be out of scope.
* Out-of-scope workflows must return `stopped=true`.
* Out-of-scope workflows must return `requests_sent=0`.
* Safe passive recon should return `requests_sent=3`.
* Risk gate should deny unknown tools.
* Risk gate should deny blocked tools.
* Risk gate should require approval for low-risk external workflows.
* Existing workflow behavior should not change when adding risk gate.

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
feature/risk-gate
docs/update-architecture
test/workflow-regression
```

Suggested commit style:

```text
Add risk gate and tool risk profiles
Update architecture docs for v0.2
Add workflow regression tests
```
