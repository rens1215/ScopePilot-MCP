# AGENTS.md

## Commenting Rules

- Generated code should include clear comments for security boundaries, risk decisions, workflow phases, and fail-closed behavior.
- Public functions should include docstrings explaining purpose, inputs, outputs, and safety constraints.
- Avoid noisy comments that simply repeat obvious code.
- Tests should include comments explaining what behavior each test protects.

---

## Project Goal

This project is an AI-assisted authorized web penetration testing platform built around MCP tools.

The system must only operate on explicitly authorized in-scope targets. It is designed to support scoped reconnaissance, controlled validation, evidence collection, prioritization, finding summarization, and reproducible report generation.

This project is not an unrestricted attack automation tool. Every external action must pass scope validation, risk policy, and workflow safety rules.

---

## Current Stable Version

Current stable version:

```text
v0.1-safe-passive-recon
```

Current completed capabilities:

* MCP server integration with LM Studio
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
* Git version control
* Basic logging
* Simplified LM Studio toolbox

Current exposed MCP tools should stay minimal.

Recommended exposed tools:

* `tool_check_scope`
* `tool_safe_http_probe_workflow`
* `tool_safe_security_headers_workflow`
* `tool_safe_cors_observation_workflow`
* `tool_safe_passive_recon_workflow`
* `tool_summarize_findings`
* `tool_write_report_draft`

Low-level tools should generally not be exposed directly to LM Studio unless explicitly required.

---

## Next Milestone

Next milestone:

```text
v0.2-risk-gate-and-execution-policy
```

Codex should prioritize implementing the risk control layer.

Required files for v0.2:

* `agent/__init__.py`
* `agent/risk_gate.py`
* `agent/approval_controller.py`
* `tools/policy_loader.py`
* `config/tool_risk_profiles.json`
* `tests/test_risk_gate.py`
* `docs/TOOL_RISK_MODEL.md`

Optional after tests pass:

* Add `tool_evaluate_action_risk` to `server.py`

Codex must not implement new vulnerability workflows before the risk gate and execution policy are complete.

---

## Architecture Rules

* `server.py` must only contain MCP tool wrappers.
* `server.py` must not contain workflow logic.
* `tools/` contains reusable low-level utilities.
* `validators/` contains conservative validation and false-positive filtering logic.
* `workflows/` contains scoped multi-step workflows.
* `agent/` contains planning, risk gate, approval, execution state, and task routing logic.
* `config/` contains scope, scan policy, false-positive rules, and tool risk profiles.
* `skills/agent_runtime/` contains task-specific knowledge for the future runtime AI penetration testing agent.
* `skills/codex_dev/` contains project maintenance guidance for Codex.
* `docs/` contains architecture, schema, roadmap, risk model, and test plan documentation.
* `tests/` contains regression tests.
* `data/` contains runtime logs and findings and must not be committed except `.gitkeep`.

---

## Layer Responsibilities

### MCP Layer

Location:

```text
server.py
```

Responsibilities:

* Register MCP tools.
* Call workflow or utility functions.
* Return structured results to LM Studio.

Rules:

* Keep `server.py` thin.
* Do not place business logic in `server.py`.
* Do not perform raw HTTP requests in `server.py`.
* Do not modify workflow behavior from `server.py`.

---

### Agent Layer

Location:

```text
agent/
```

Responsibilities:

* Planning
* Risk evaluation
* Approval decision
* Execution state
* Task routing

Rules:

* Agent layer must not directly send HTTP requests.
* Agent layer must not bypass `scope_guard`.
* Medium-risk and high-risk actions must go through `risk_gate`.
* Planner must produce an execution plan, not directly execute tools.

---

### Workflow Layer

Location:

```text
workflows/
```

Responsibilities:

* Check scope.
* Call low-level tools.
* Call validators.
* Save findings.
* Return safety metadata.
* Log execution steps.

Every workflow that may send an external request must:

1. Call `check_scope()` before any external request.
2. Stop immediately if target is out of scope.
3. Return `safety.requests_sent`.
4. Log workflow start, scope result, request start, request completion, validation result, save result, and workflow completion.
5. Avoid storing sensitive data.

Every workflow should return a structure similar to:

```json
{
  "target": "",
  "scope": {},
  "summary": {},
  "validator_result": {},
  "saved_result": {},
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

---

### Tool Layer

Location:

```text
tools/
```

Responsibilities:

* Low-level reusable utilities.
* HTTP probing.
* Header extraction.
* Scope checking.
* Endpoint classification.
* Storage.
* Logging.
* Policy loading.
* Priority scoring.
* Finding summarization.

Rules:

* Low-level tools should be deterministic when possible.
* Tools should not decide reportability by themselves.
* Tools should not store secrets, cookies, tokens, personal data, payment data, or full sensitive response bodies.
* External-request tools should be called by workflows, not directly by the runtime AI.

---

### Validator Layer

Location:

```text
validators/
```

Responsibilities:

* Classify observations.
* Reduce false positives.
* Determine status, severity, confidence, and reportability.
* Provide reasoning and false-positive notes.

Validators must not:

* Send HTTP requests.
* Modify state.
* Store findings.
* Execute payloads.
* Make unsupported claims.

Validator output should follow this pattern:

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

---

### Skill Layer

Location:

```text
skills/
```

There are two types of skills:

```text
skills/agent_runtime/
skills/codex_dev/
```

#### `skills/agent_runtime/`

Used by the future runtime AI penetration testing agent.

Purpose:

* Guide reasoning during security testing.
* Define decision rules.
* Define evidence requirements.
* Define false-positive rules.
* Define escalation rules.
* Define output schema.

Runtime skills are not exploit scripts.

Runtime skills should not contain unrestricted payload lists, brute-force logic, credential attacks, or destructive instructions.

#### `skills/codex_dev/`

Used by Codex for project maintenance.

Purpose:

* Explain how to add workflows.
* Explain how to write tests.
* Explain how to maintain architecture.
* Explain coding rules.

---

### Config Layer

Location:

```text
config/
```

Responsibilities:

* Scope definition
* Scan policy
* False-positive rules
* Tool risk profiles

Important files:

```text
config/scope.json
config/scan_policy.json
config/false_positive_rules.json
config/tool_risk_profiles.json
```

Rules:

* `scope.json` is the source of truth for target authorization.
* `tool_risk_profiles.json` is the source of truth for tool risk classification.
* `false_positive_rules.json` should not be empty; use `[]` if no rules exist yet.
* `scan_policy.json` should define global safety limits.

---

### Data Layer

Location:

```text
data/
```

Runtime files:

```text
data/findings.jsonl
data/mcp.log
data/evidence.jsonl
```

Rules:

* Runtime data must not be committed.
* Only `data/.gitkeep` should be committed.
* Findings must not include cookies, tokens, secrets, personal data, payment data, or full sensitive response bodies.
* Evidence should favor metadata, hashes, summaries, and reproducible steps over sensitive content.

---

## Safety Rules

* Every workflow must call `check_scope()` before any external request.
* Every workflow must return a `safety` object.
* Every external workflow must report `requests_sent`.
* Every external workflow must log start, scope result, request start, request completion, validation result, save result, and workflow completion.
* No workflow may perform brute force.
* No workflow may perform DoS or stress testing.
* No workflow may perform mass fuzzing.
* No workflow may perform credential stuffing.
* No workflow may perform destructive actions.
* No workflow may perform unrestricted exploit chaining.
* No workflow may store cookies, tokens, secrets, personal data, payment data, or sensitive response bodies.
* Medium-risk and high-risk validation must be behind `risk_gate` and explicit approval.
* Unknown-risk tools must be denied by default.

---

## Risk Levels

### Safe

No external request.

Examples:

* Scope check
* Risk evaluation
* Finding summarization
* Report draft generation

Default:

```text
Allow
```

---

### Low

External request, but non-destructive and limited.

Examples:

* Safe HTTP probe
* Security headers check
* CORS observation
* Passive recon workflow

Default:

```text
Ask / approval required
```

---

### Medium

More targeted validation or multiple requests.

Examples:

* JS endpoint extraction
* Robots/security.txt/sitemap workflow
* Exposed public file observation
* Open redirect controlled observation
* GraphQL observation

Default:

```text
Explicit approval required
```

---

### High

Sensitive validation requiring credentials, controlled account setup, or authorization-specific testing.

Examples:

* Auth/access-control review
* IDOR validation
* Authenticated API comparison
* State-sensitive validation

Default:

```text
Explicit approval required + strict request limit + evidence rules
```

---

### Blocked

Never automate.

Examples:

* Brute force
* Credential stuffing
* DoS
* Mass fuzzing
* Unrestricted exploit chains
* Real data exfiltration
* Unauthorized access attempts
* Destructive actions

Default:

```text
Deny
```

---

## Coding Rules

* Keep `server.py` thin.
* Prefer deterministic Python logic over LLM judgment for validation.
* Prefer workflow-level MCP tools over exposing low-level tools to LM Studio.
* Do not add new MCP tools unless necessary.
* Add or update tests when changing workflow behavior.
* Do not change scope guard behavior unless explicitly requested.
* Do not commit runtime files such as `data/findings.jsonl` or `data/mcp.log`.
* Do not add exploit, fuzzing, brute-force, credential attack, or destructive validation logic unless explicitly requested and guarded by risk policy.
* When uncertain, update docs first instead of changing runtime code.

---

## Codex Task Rules

Codex must work in small steps.

For each task:

* Read this file first.
* Read relevant docs under `docs/`.
* Modify only files explicitly allowed by the user.
* Do not modify `scope_guard.py` unless explicitly requested.
* Do not modify existing workflow behavior unless explicitly requested.
* Do not expose new MCP tools unless explicitly requested.
* Do not add exploit, fuzzing, brute force, credential attack, or destructive validation logic.
* If a task requires a new workflow, also add or update tests.
* If uncertain, update docs first instead of changing runtime code.
* Explain what changed.
* Explain how to test it.

---

## v0.2 Codex Priority

When asked what to do next, Codex should prioritize:

1. Add `agent/risk_gate.py`
2. Add `agent/approval_controller.py`
3. Add `tools/policy_loader.py`
4. Add `config/tool_risk_profiles.json`
5. Add `tests/test_risk_gate.py`
6. Add `docs/TOOL_RISK_MODEL.md`
7. Only after tests pass, optionally add `tool_evaluate_action_risk` to `server.py`

Codex must not implement new vulnerability workflows before v0.2 risk gate is complete.

---

## v0.2 Acceptance Criteria

v0.2 is complete when:

1. `risk_gate.py` can classify tool actions as `safe`, `low`, `medium`, `high`, `blocked`, or `unknown`.
2. `tool_risk_profiles.json` contains risk profiles for all exposed MCP tools.
3. `approval_controller.py` can build approval request objects.
4. `tests/test_risk_gate.py` passes.
5. Existing workflow tests still pass.
6. No existing workflow behavior is changed.
7. No new external-request workflow is added.
8. `server.py` remains thin.
