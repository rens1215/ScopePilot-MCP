# Test Plan

## Purpose

This document defines the current test strategy for `MCP_SERVER_FOR_LLM_HACKER`.

The goal of the test suite is to ensure that the MCP toolbox remains safe, stable, bounded, and compatible with LM Studio while supporting authorized in-scope reconnaissance, attack surface inventory, result standardization, and report preparation.

The tests must protect the following guarantees:

* Scope checks run before external workflows.
* Out-of-scope targets produce `requests_sent=0`.
* Request budgets are enforced.
* Workflows do not fuzz, brute force, exploit, submit forms, use credentials, or perform state-changing actions.
* Workflows do not store cookies, tokens, secrets, personal data, payment data, or full sensitive response bodies.
* MCP tool names and signatures remain stable.
* Refactors do not change existing workflow behavior unless intentionally documented and tested.

---

## Current Stable Version

```text
v0.5-core-refactor-and-result-standardization
```

---

## Test Categories

### 1. MCP Registration Tests

File:

```text
tests/test_mcp_tool_registration.py
```

Purpose:

Ensure that LM Studio still sees the same MCP toolbox after `server.py` was split into `mcp_tools/`.

Must verify:

* All expected MCP tool names are registered.
* Registration does not execute workflows.
* Registration does not send network requests.
* Tool signatures remain stable.

Expected MCP tools:

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

### 2. Scope and Risk Gate Tests

Files:

```text
tests/test_risk_gate.py
```

Purpose:

Ensure risk policy is enforced before tool execution.

Must verify:

* Known tools have correct risk profiles.
* Unknown tools are denied or treated as unknown.
* Tools requiring approval are blocked when `user_approved=false`.
* Approved tools can pass when policy allows.
* Blocked tools cannot be executed by approval alone.
* Request budget metadata is preserved.

Important behavior:

```text
missing risk profile → deny
blocked risk level → deny
requires approval + not approved → deny
requires approval + approved → allow only if policy permits
```

---

### 3. Shared Helper Tests

Files:

```text
tests/test_safety_metadata.py
tests/test_result_schema.py
tests/test_http_result_utils.py
tests/test_inventory_candidate_builder.py
```

Purpose:

Protect v0.5 shared helper behavior.

#### `test_safety_metadata.py`

Must verify:

* Default safety metadata is safe.
* `requests_sent` is normalized.
* Negative request counts are not preserved.
* Non-numeric request counts do not crash.
* `scan_level` is preserved.
* `crawling=True` can be represented.
* `state_changing` defaults to `False`.

#### `test_result_schema.py`

Must verify:

* Standard workflow result fields are present.
* Blocked result uses `stopped=True`.
* Blocked result uses `safety.requests_sent=0`.
* Blocked result uses `safety.scan_level=blocked`.
* Observations and errors can be appended safely.
* Missing list fields do not crash helper functions.

#### `test_http_result_utils.py`

Must verify:

* HTTP helper exceptions become `request_error`.
* Non-dict HTTP helper results become `request_error`.
* Content-Type extraction is normalized.
* Charset is stripped.
* Safe headers are preserved.
* Sensitive headers are removed.
* Full response bodies are not included in observations.
* No real network request is sent during tests.

#### `test_inventory_candidate_builder.py`

Must verify:

* Safe evidence metadata is preserved.
* Full bodies are removed.
* Cookies, authorization material, tokens, secrets, API keys, personal data, and payment data are removed.
* Inventory candidates include validator metadata.
* Empty URLs do not crash.
* Helper does not import network libraries or workflows.

---

### 4. v0.1 Base Observation Workflow Tests

Files:

```text
tests/test_safe_http_probe_workflow.py
tests/test_safe_security_headers_workflow.py
tests/test_safe_cors_observation_workflow.py
tests/test_safe_passive_recon_workflow.py
```

Purpose:

Ensure early safe workflows remain useful after v0.5 refactoring.

#### `test_safe_http_probe_workflow.py`

Must verify:

* Out-of-scope target stops before request.
* In-scope target calls HTTP helper once.
* HTTP helper exception does not crash.
* HTTP helper non-dict result does not crash.
* `requests_sent <= 1`.
* No sensitive headers are preserved.
* Full response body is not preserved.

#### `test_safe_security_headers_workflow.py`

Must verify:

* Out-of-scope target stops before request.
* In-scope target calls security header helper once.
* Helper exception does not crash.
* Helper non-dict result does not crash.
* `requests_sent <= 1`.
* Only safe security header metadata is preserved.
* Full response body is not preserved.

#### `test_safe_cors_observation_workflow.py`

Must verify:

* Out-of-scope target stops before request.
* In-scope target calls CORS helper once.
* Helper exception does not crash.
* Helper non-dict result does not crash.
* `requests_sent <= 1`.
* Harmless default origin is used.
* Credential-like test origins are replaced.
* No credentials, cookies, tokens, or full response bodies are preserved.

#### `test_safe_passive_recon_workflow.py`

Must verify:

* Out-of-scope target does not call child workflows.
* In-scope target calls:

  * `safe_http_probe_workflow`
  * `safe_security_headers_workflow`
  * `safe_cors_observation_workflow`
* Child workflow exception does not crash parent.
* Child workflow non-dict result does not crash parent.
* Request budget remains 3.
* Aggregated summary does not preserve sensitive data or full response bodies.

---

### 5. v0.4 Attack Surface Inventory Workflow Tests

Files:

```text
tests/test_robots_securitytxt_workflow.py
tests/test_sitemap_parser_workflow.py
tests/test_js_endpoint_extraction_workflow.py
tests/test_bounded_crawl_foundation.py
tests/test_bounded_crawl_workflow.py
tests/test_attack_surface_inventory.py
```

Purpose:

Ensure inventory workflows remain bounded and safe.

#### `test_robots_securitytxt_workflow.py`

Must verify:

* Out-of-scope target sends 0 requests.
* Only fixed metadata paths are requested:

  * `/robots.txt`
  * `/.well-known/security.txt`
  * `/sitemap.xml`
* Robots `Disallow` paths are not requested.
* Request budget is 3.
* Sensitive headers are not stored.

#### `test_sitemap_parser_workflow.py`

Must verify:

* Out-of-scope target sends 0 requests.
* Only `/sitemap.xml` is requested.
* URLs listed inside sitemap are not requested.
* Valid sitemap entries become inventory candidates.
* `max_urls` is enforced.
* Oversized sitemap is not parsed.
* Invalid XML becomes `parse_error`.
* HTTP helper exception and non-dict result do not crash workflow.
* Out-of-scope sitemap URLs are skipped.

#### `test_js_endpoint_extraction_workflow.py`

Must verify:

* Out-of-scope target sends 0 requests.
* Workflow requests target HTML once.
* Workflow requests only same-host or in-scope JS.
* Default JS file limit is 20.
* Hard JS file cap is 30.
* Hard total request cap is 31.
* HTML content-type gate is enforced.
* JS content-type gate is enforced.
* Oversized JS is skipped.
* JS is not executed or evaluated.
* Extracted API endpoints are not requested.
* Endpoint candidates are deduplicated.
* `safety.crawling=false`.

#### `test_bounded_crawl_foundation.py`

Must verify:

* HTML links are extracted locally.
* Script src values are extracted locally.
* Relative URLs are normalized.
* Unsupported schemes are rejected.
* Form actions are not used as crawl targets.
* Crawl queue enforces:

  * dedupe
  * max depth
  * max pages
  * scope filtering
* No HTTP request is sent.

#### `test_bounded_crawl_workflow.py`

Must verify:

* Out-of-scope target sends 0 requests.
* `max_pages` is enforced.
* `max_depth` is enforced.
* `max_requests` is enforced.
* Hard request cap is 30.
* Out-of-scope links are not requested.
* Form actions are not requested.
* Unsupported content-type is not parsed.
* HTTP helper exception and non-dict result do not crash.
* Script src becomes inventory candidate but is not downloaded.
* JS API endpoints are not requested.
* `safety.crawling=true`.

---

## Full Regression Test Command

Run this before every merge or tag:

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

---

## Test Rules

All tests must follow these rules:

* Use mocks for external behavior.
* Do not send real network requests.
* Do not require real credentials.
* Do not write sensitive data.
* Do not execute exploit logic.
* Do not fuzz or brute force.
* Do not rely on external services.
* Do not weaken safety assertions to make tests pass.
* Do not remove request-budget assertions without updating architecture and risk profiles.

---

## Merge Criteria

A change may be merged only if:

1. Relevant tests pass.
2. Full regression tests pass before version tag.
3. No request budget was changed without explicit documentation.
4. No new MCP tool was exposed without a risk profile.
5. No workflow bypasses scope guard.
6. No workflow stores sensitive data.
7. No workflow introduces exploit, fuzzing, brute force, credential testing, form submission, or state-changing behavior.
8. Documentation is updated when behavior changes.

---

## Tagging Criteria

Before creating a version tag:

1. Run full regression tests.
2. Check `git status`.
3. Check `git log --oneline --graph --decorate --all`.
4. Confirm `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, and this test plan reflect current behavior.
5. Create the tag only from a clean, stable branch.

Example:

```powershell
git status
git log --oneline --graph --decorate --all
git tag v0.5-core-refactor-and-result-standardization
```
