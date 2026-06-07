# Architecture

## Project Name

```text
MCP_SERVER_FOR_LLM_HACKER
```

---

## System Goal

本專案是一個以 MCP tools 為核心的 AI-assisted authorized web security testing platform。

系統目標是讓 runtime AI agent 可以在明確授權、明確 in-scope 的目標上，自動化執行：

* scope checking
* risk evaluation
* approval request
* safe reconnaissance
* attack surface inventory
* controlled validation planning
* evidence organization
* finding prioritization
* finding summarization
* report draft generation

本專案不是 unrestricted attack automation tool。

任何 external action 都必須遵守：

* scope guard
* risk gate
* approval policy
* request limits
* workflow safety rules
* evidence rules
* sensitive-data minimization

---

## Current Stable Version

Current stable version:

```text
v0.5-core-refactor-and-result-standardization
```

v0.5 已完成，並且是 refactor / standardization milestone。

v0.5 沒有新增：

* exploit automation
* fuzzing
* brute force
* credential testing
* form submission
* state-changing action
* destructive action
* new external request behavior
* new request budgets
* new vulnerability validation

---

## Next Target Version

Next milestone:

```text
v0.6-controlled-validation
```

v0.6 的目標是基於 v0.4 attack surface inventory 與 v0.5 standardized helpers，加入**受控漏洞驗證規劃與低風險 observation workflows**。

v0.6 不應該變成 unrestricted exploit automation。

v0.6 的核心目標是：

```text
從 inventory candidates 中挑選高價值 endpoint
→ 建立 validation plan
→ 進行 bounded controlled observation
→ 收集安全 evidence
→ 產生 candidate finding
→ 明確標記 limitation 與 manual validation need
```

---

# Completed Through v0.5

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
* Shared safety metadata helper
* Shared result schema helper
* Shared HTTP result utility helper
* Shared inventory candidate builder
* Refactored v0.1 base workflows
* Refactored v0.4 inventory workflows
* Refactored passive recon workflow
* Split MCP wrappers into `mcp_tools/`
* MCP tool registration tests
* Test plan documentation
* Roadmap documentation
* Result schema documentation

---

# Current Exposed MCP Tools

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

v0.6 may add new MCP tools only after:

1. workflow exists
2. tests exist
3. risk profile exists
4. docs are updated
5. code review passes
6. tool is intentionally exposed through `mcp_tools/workflow_tools.py`

---

# Current Architecture Overview

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
Safe Workflow / Controlled Validation Workflow
    ↓
Low-level Tools + Validators
    ↓
Standard Result Schema
    ↓
Storage / Summary / Report Draft
```

---

# Layer Responsibilities

## MCP Layer

Location:

```text
server.py
mcp_tools/
```

Current structure:

```text
server.py
    MCP composition root only

mcp_tools/scope_tools.py
    registers tool_check_scope

mcp_tools/risk_tools.py
    registers tool_evaluate_action_risk

mcp_tools/workflow_tools.py
    registers safe workflow wrappers

mcp_tools/report_tools.py
    registers report tools
```

Rules:

* `server.py` must remain thin.
* `server.py` must not send HTTP requests.
* `server.py` must not implement workflow logic.
* `mcp_tools/*` must remain thin wrappers.
* MCP tool names must remain stable.
* New exposed tools must have risk profiles.

---

## Agent Layer

Location:

```text
agent/
```

Current components:

```text
agent/risk_gate.py
agent/approval_controller.py
```

Future v0.7 candidates:

```text
agent/planner.py
agent/execution_state.py
agent/task_router.py
agent/evidence_review_gate.py
```

Responsibilities:

* Evaluate tool risk.
* Build approval requests.
* Prevent unknown tool execution.
* Require explicit approval when needed.
* Future: plan multi-step validation safely.
* Future: track execution state and stop conditions.

Rules:

* Must not send HTTP requests directly.
* Must not bypass scope guard.
* Must not bypass risk gate.
* Must deny unknown tools by default.
* Must not perform exploit planning that exceeds approved workflow boundaries.

---

## Workflow Layer

Location:

```text
workflows/
```

Current workflows:

```text
safe_http_probe_workflow.py
safe_security_headers_workflow.py
safe_cors_observation_workflow.py
safe_passive_recon_workflow.py
safe_robots_securitytxt_workflow.py
safe_sitemap_parser_workflow.py
safe_js_endpoint_extraction_workflow.py
safe_bounded_crawl_workflow.py
```

v0.6 candidate workflows:

```text
controlled_open_redirect_observation_workflow.py
controlled_exposed_file_observation_workflow.py
controlled_graphql_observation_workflow.py
controlled_authz_review_preparation_workflow.py
controlled_idor_validation_preparation_workflow.py
validation_plan_builder_workflow.py
```

Responsibilities:

* Check scope before external requests.
* Use risk-aware request budgets.
* Call low-level tools.
* Call validators.
* Save safe observations or candidate findings when designed.
* Return standardized workflow result objects.
* Return safety metadata.

Rules:

* No workflow may perform unrestricted exploitation.
* No workflow may perform brute force.
* No workflow may perform credential stuffing.
* No workflow may perform DoS.
* No workflow may submit forms unless a future workflow explicitly supports a safe, approved, non-destructive action.
* No workflow may perform state-changing behavior unless explicitly approved and documented.
* No workflow may store cookies, tokens, secrets, personal data, payment data, or full sensitive response bodies.

---

## Shared Helper Layer

Location:

```text
tools/safety_metadata.py
tools/result_schema.py
tools/http_result_utils.py
tools/inventory_candidate_builder.py
```

Responsibilities:

* Build consistent safety metadata.
* Build stable workflow result shapes.
* Normalize HTTP helper result handling.
* Filter sensitive headers and body content.
* Build sanitized inventory candidates.

Rules:

* Helpers must not add external request behavior unless explicitly designed.
* Helpers must not claim vulnerability confirmation.
* Helpers must not store sensitive data.
* Helpers must not hide risky behavior in safety metadata.

---

## Tool Layer

Location:

```text
tools/
```

Current important tools:

```text
scope_guard.py
http_probe.py
security_headers.py
endpoint_classifier.py
priority_scorer.py
finding_summarizer.py
report_writer.py
storage.py
logger.py
policy_loader.py
skill_loader.py
url_normalizer.py
endpoint_inventory.py
js_endpoint_extractor.py
html_link_extractor.py
crawl_queue.py
safety_metadata.py
result_schema.py
http_result_utils.py
inventory_candidate_builder.py
```

v0.6 candidate tools:

```text
validation_plan_builder.py
evidence_sanitizer.py
controlled_payloads.py
open_redirect_observer.py
exposed_file_observer.py
graphql_observer.py
authz_test_case_builder.py
idor_test_case_builder.py
```

Rules:

* Tool functions should be small and reusable.
* Low-level tools should not bypass workflow safety boundaries.
* Any tool that can generate requests must be called through a workflow.
* Any tool that handles evidence must sanitize sensitive data.

---

## Validator Layer

Location:

```text
validators/
```

Current validators:

```text
header_validator.py
cors_validator.py
inventory_validator.py
```

v0.6 candidate validators:

```text
open_redirect_validator.py
exposed_file_validator.py
graphql_validator.py
authz_validator.py
idor_validator.py
evidence_validator.py
```

Responsibilities:

* Conservative classification.
* False-positive reduction.
* Reportability guidance.
* Evidence sanity checks.

Rules:

* Validators must not send requests.
* Validators must not modify state.
* Validators must not execute payloads.
* Validators must not make unsupported vulnerability claims.
* Validators should classify results as:

  * observation
  * candidate_finding
  * needs_manual_validation
  * confirmed_finding only when future controlled validation rules allow it

---

## Config Layer

Location:

```text
config/
```

Current config:

```text
scope.json
scan_policy.json
false_positive_rules.json
tool_risk_profiles.json
```

v0.6 config candidates:

```text
validation_policy.json
controlled_payload_policy.json
evidence_rules.json
```

Responsibilities:

* Define allowed scope.
* Define scan policy.
* Define risk profile.
* Define false-positive handling.
* Future: define validation-specific policies.

Rules:

* New MCP tools must be added to `tool_risk_profiles.json`.
* Unknown tools must remain denied.
* Medium/high-risk validation tools must require explicit approval.
* Request budgets must be documented and tested.

---

## Data Layer

Location:

```text
data/
```

Current data files:

```text
findings.jsonl
evidence.jsonl
endpoint_inventory.jsonl
mcp.log
```

v0.6 data candidates:

```text
validation_plans.jsonl
validation_evidence.jsonl
execution_state.jsonl
```

Rules:

* Do not store sensitive data.
* Do not store full response bodies.
* Do not store cookies, tokens, secrets, personal data, or payment data.
* Evidence should be minimized and reproducible.
* Store metadata, not raw secrets.

---

## Documentation Layer

Location:

```text
docs/
```

Current docs:

```text
ARCHITECTURE.md
ATTACK_SURFACE_INVENTORY.md
TOOL_RISK_MODEL.md
RUNTIME_SKILLS.md
RESULT_SCHEMA.md
ROADMAP.md
TEST_PLAN.md
```

v0.6 docs candidates:

```text
CONTROLLED_VALIDATION.md
EVIDENCE_RULES.md
VALIDATION_POLICY.md
```

Rules:

* Docs must describe safety boundaries.
* Docs must not include exploit payloads for uncontrolled use.
* Docs must clearly separate inventory from validation.
* Docs must not claim the project can automatically compromise targets.

---

# Current Request Budgets

Existing request budgets:

| Workflow                               | Risk level | Max requests |
| -------------------------------------- | ---------- | -----------: |
| `safe_http_probe_workflow`             | low        |            1 |
| `safe_security_headers_workflow`       | low        |            1 |
| `safe_cors_observation_workflow`       | low        |            1 |
| `safe_passive_recon_workflow`          | low        |            3 |
| `safe_robots_securitytxt_workflow`     | low        |            3 |
| `safe_sitemap_parser_workflow`         | low        |            1 |
| `safe_js_endpoint_extraction_workflow` | medium     |           31 |
| `safe_bounded_crawl_workflow`          | medium     |           30 |

v0.6 must not change these budgets unless explicitly reviewed, documented, tested, and approved.

---

# v0.6 Controlled Validation Strategy

## v0.6 Goal

v0.6 should introduce controlled validation preparation and bounded observation workflows.

The goal is not to exploit targets.

The goal is to help the AI agent answer:

```text
Which inventory candidates are worth validating?
What is the safest validation plan?
What evidence is needed?
What request budget is allowed?
What manual steps are required?
What should not be automated?
```

---

## v0.6 Core Principles

v0.6 must follow these principles:

1. Inventory is not vulnerability proof.
2. Validation must be selected and bounded.
3. Every validation action must pass scope guard.
4. Every validation action must pass risk gate.
5. Medium/high-risk workflows require explicit approval.
6. Request limits must be hard enforced.
7. Evidence must be minimized.
8. Sensitive data must not be stored.
9. Workflows must have stop conditions.
10. Validation results must avoid overclaiming.

---

## v0.6 Recommended Build Order

### Step 1 — Validation Plan Builder

Files:

```text
tools/validation_plan_builder.py
workflows/validation_plan_builder_workflow.py
tests/test_validation_plan_builder.py
```

Purpose:

* Take inventory candidates.
* Select high-value endpoints.
* Propose safe validation plans.
* Do not send requests.
* Do not validate vulnerabilities.
* Do not generate exploit chains.

Output:

```text
validation_plan
selected_candidates
risk_notes
required_approval
recommended_workflow
manual_validation_needed
```

Risk level:

```text
safe
```

Reason:

No external requests.

---

### Step 2 — Evidence Sanitizer

Files:

```text
tools/evidence_sanitizer.py
tests/test_evidence_sanitizer.py
```

Purpose:

* Sanitize evidence before saving.
* Remove sensitive headers.
* Remove full response bodies.
* Remove credential-like material.
* Normalize evidence metadata.

Risk level:

```text
safe
```

Reason:

No external requests.

---

### Step 3 — Controlled Open Redirect Observation

Files:

```text
workflows/controlled_open_redirect_observation_workflow.py
validators/open_redirect_validator.py
tests/test_controlled_open_redirect_observation_workflow.py
```

Purpose:

* Safely observe whether a specific redirect parameter appears to redirect to a harmless controlled domain.
* Only test explicitly selected URL candidates.
* Use harmless destination such as:

  * `https://example-redirect.invalid`
* Do not follow into real third-party targets for impact.
* Do not chain redirects.
* Do not test many parameters automatically.

Risk level:

```text
medium
```

Request budget suggestion:

```text
max 3 requests
```

Safety rules:

* Scope check first.
* Risk gate required.
* Explicit approval required.
* No fuzzing.
* No parameter brute force.
* No crawling.
* No exploit chain.
* No credentialed request.
* No state-changing action.

---

### Step 4 — Controlled Exposed File Observation

Files:

```text
workflows/controlled_exposed_file_observation_workflow.py
validators/exposed_file_validator.py
tests/test_controlled_exposed_file_observation_workflow.py
```

Purpose:

* Observe explicitly selected known file candidates.
* Examples:

  * `.well-known/security.txt`
  * `/.git/config` only if explicitly selected and policy allows
  * `/backup.zip` only if discovered and explicitly selected
* Do not download large files.
* Do not store file contents.
* Only store status code, content type, body size, hash prefix if safe, and headers summary.

Risk level:

```text
medium
```

Request budget suggestion:

```text
max 3 requests
```

Safety rules:

* Do not recursively enumerate files.
* Do not brute force filenames.
* Do not download large content.
* Do not store secrets.
* Stop if content appears sensitive.

---

### Step 5 — Controlled GraphQL Observation

Files:

```text
workflows/controlled_graphql_observation_workflow.py
validators/graphql_validator.py
tests/test_controlled_graphql_observation_workflow.py
```

Purpose:

* Safely observe GraphQL endpoint metadata.
* Optionally check whether introspection appears enabled only if allowed by policy.
* Use minimal non-destructive query only.
* Do not dump schema automatically.
* Do not enumerate fields aggressively.

Risk level:

```text
medium
```

Request budget suggestion:

```text
max 2 requests
```

Safety rules:

* Explicit approval required.
* No brute force.
* No field enumeration.
* No credentialed query.
* No mutation.
* No introspection dump storage.
* Do not store sensitive response bodies.

---

### Step 6 — Authz / IDOR Validation Preparation

Files:

```text
workflows/controlled_authz_review_preparation_workflow.py
workflows/controlled_idor_validation_preparation_workflow.py
validators/authz_validator.py
validators/idor_validator.py
tests/test_controlled_authz_review_preparation_workflow.py
tests/test_controlled_idor_validation_preparation_workflow.py
```

Purpose:

* Prepare validation checklist.
* Identify required accounts, roles, permissions, and data boundaries.
* Do not perform automated IDOR exploitation.
* Do not access unauthorized data.
* Do not test real user data.

Risk level:

```text
safe or high
```

Recommended v0.6 approach:

```text
Preparation only = safe
Credentialed validation = future high-risk workflow, not v0.6 default
```

Safety rules:

* No credential use in v0.6 unless explicitly designed later.
* No unauthorized data access.
* No account abuse.
* No object ID brute force.
* No mass enumeration.

---

# v0.6 Non-Goals

v0.6 must not implement:

```text
unrestricted exploit automation
exploit chaining
SQL injection exploitation
XSS exploitation
SSRF exploitation
RCE exploitation
credential stuffing
brute force
DoS
mass fuzzing
mass parameter discovery
state-changing validation
destructive actions
automatic data exfiltration
automatic bounty submission
```

v0.6 should focus on controlled validation planning and limited observation.

---

# v0.6 Expected New MCP Tools

Do not expose these until implementation, tests, docs, and risk profiles are complete.

Candidate MCP tools:

```text
tool_build_validation_plan
tool_controlled_open_redirect_observation
tool_controlled_exposed_file_observation
tool_controlled_graphql_observation
tool_prepare_authz_review
tool_prepare_idor_validation
```

Each new tool must have:

* workflow implementation
* tests
* risk profile
* docs
* stable wrapper signature
* no direct request logic in MCP wrapper
* explicit safety docstring

---

# v0.6 Result Schema Requirements

v0.6 workflows must follow `docs/RESULT_SCHEMA.md`.

Every controlled validation workflow should include:

```text
target
stopped
reason
scope
observations
inventory_candidates
findings
errors
warnings
summary
safety
validation_plan
evidence
limitations
manual_validation_required
```

Validation result statuses should be conservative:

```text
observation
candidate_finding
needs_manual_validation
not_applicable
blocked
```

Avoid `confirmed_finding` unless future policy explicitly allows it and evidence is sufficient.

---

# v0.6 Evidence Rules

Controlled validation workflows must use evidence minimization.

Allowed evidence:

```text
status_code
content_type
body_size
headers_summary
redirect_location_host
redirect_location_path
graphql_error_type
safe response metadata
hash prefix of non-sensitive content
validation notes
request count
```

Disallowed evidence:

```text
full response body
cookies
authorization headers
tokens
secrets
API keys
session IDs
personal data
payment data
private user data
large file contents
database dumps
source code dumps
credential material
```

---

# v0.6 Testing Requirements

Every v0.6 workflow must test:

* out-of-scope sends 0 requests
* risk budget is enforced
* helper exception does not crash
* helper non-dict result does not crash
* sensitive data is not stored
* full response body is not stored
* request count is accurate
* no fuzzing
* no brute force
* no credentialed request unless explicitly designed
* no state-changing behavior
* approval-required risk profile exists

---

# v0.7 Future Direction

Future milestone:

```text
v0.7-agent-planning-and-evidence-pipeline
```

v0.7 should improve orchestration rather than add more validation types.

Recommended v0.7 focus:

## 1. Agent Planner

Files:

```text
agent/planner.py
agent/task_router.py
tests/test_agent_planner.py
```

Purpose:

* Convert user intent into safe task sequence.
* Choose correct workflow based on target and inventory.
* Prevent unsafe tool chains.
* Enforce order:

  * scope check
  * risk evaluation
  * approval
  * execution
  * summary

## 2. Execution State

Files:

```text
agent/execution_state.py
tests/test_execution_state.py
```

Purpose:

* Track what the AI has already done.
* Avoid duplicate requests.
* Track request budgets across a session.
* Track approvals.
* Track stopped workflows.
* Track inventory candidates already processed.

## 3. Evidence Pipeline

Files:

```text
tools/evidence_sanitizer.py
tools/evidence_store.py
validators/evidence_validator.py
tests/test_evidence_pipeline.py
```

Purpose:

* Normalize evidence.
* Sanitize sensitive data.
* Link evidence to findings.
* Support reproducible report drafts.
* Prevent unsafe evidence storage.

## 4. Report Template System

Files:

```text
tools/report_templates.py
docs/REPORTING.md
tests/test_report_templates.py
```

Purpose:

* Generate structured report drafts.
* Separate observation / candidate finding / confirmed finding.
* Include limitations and manual validation notes.
* Avoid unsupported impact claims.

## 5. Session Summary

Files:

```text
tools/session_summary.py
tests/test_session_summary.py
```

Purpose:

* Summarize executed tools.
* Summarize request counts.
* Summarize findings and candidates.
* Summarize next safe steps.
* Help user resume testing later.

---

# v0.7 Non-Goals

v0.7 should not add unrestricted exploit automation.

v0.7 should not add:

```text
automatic exploit chaining
brute force automation
credential stuffing
DoS workflows
mass fuzzing
unapproved credentialed testing
automatic bounty submission
```

v0.7 should make the system smarter, safer, and easier to operate.

---

# Recommended Branch Strategy

For v0.6:

```text
feature/controlled-validation
feature/validation-plan-builder
feature/evidence-sanitizer
feature/controlled-open-redirect-observation
feature/controlled-exposed-file-observation
feature/controlled-graphql-observation
```

For v0.7:

```text
feature/agent-planner
feature/execution-state
feature/evidence-pipeline
feature/report-template-system
feature/session-summary
```

---

# Development Rules

For every change:

1. Start from a clean Git state.
2. Create a feature branch.
3. Modify only allowed files.
4. Run targeted tests.
5. Run full regression tests before merge.
6. Check `git diff`.
7. Commit with a clear message.
8. Merge only after tests pass.
9. Tag stable milestones.

---

# Merge Criteria

A change can be merged only if:

* Relevant tests pass.
* No request budget changed without documentation.
* No new MCP tool is exposed without risk profile.
* No workflow bypasses scope guard.
* No workflow bypasses risk gate.
* No workflow stores sensitive data.
* No workflow performs unapproved state-changing behavior.
* Documentation is updated.

---

# Stable Tag Criteria

Before tagging v0.6:

1. All v0.5 regression tests pass.
2. All v0.6 new tests pass.
3. `docs/ARCHITECTURE.md` is updated.
4. `docs/ROADMAP.md` is updated.
5. `docs/TEST_PLAN.md` is updated.
6. `docs/RESULT_SCHEMA.md` is updated if schema changed.
7. `config/tool_risk_profiles.json` includes all new exposed tools.
8. `server.py` remains thin.
9. `mcp_tools/*` wrappers remain thin.
10. No uncontrolled exploit automation exists.
