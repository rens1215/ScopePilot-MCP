# Result Schema

## Purpose

This document defines the standard output schema for workflows in `MCP_SERVER_FOR_LLM_HACKER`.

Codex should reference this document when creating or refactoring workflow outputs.

The goal is to make workflow results consistent, easy for the runtime AI agent to parse, easy to test, and safe to store.

This schema is not a vulnerability report schema. It is a workflow result schema.

---

## Core Rule

Every workflow should return a dictionary.

The result should include stable top-level fields whenever possible:

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
  "safety": {}
}
```

A workflow may include additional backward-compatible fields, but it should not remove these standard fields once adopted.

---

## Standard Top-Level Fields

### `target`

Type:

```text
string
```

Purpose:

The original target provided to the workflow.

Example:

```json
"target": "https://example.com"
```

Rules:

* Must not contain secrets.
* Must not contain credentials.
* If caller passes credential-like URL, workflow should sanitize or reject where appropriate.

---

### `stopped`

Type:

```text
boolean
```

Purpose:

Indicates whether workflow execution stopped early.

Example:

```json
"stopped": true
```

Common stopped cases:

* Target is out of scope.
* Risk policy blocks execution.
* Required approval is missing.
* Required helper is unavailable and workflow cannot proceed safely.

Rules:

* Out-of-scope results must use `stopped=true`.
* Non-fatal request errors do not always require `stopped=true`; they can be represented as observations/errors.

---

### `reason`

Type:

```text
string
```

Purpose:

Human-readable reason for stop, block, failure, or important state.

Example:

```json
"reason": "Target is not in scope."
```

Rules:

* Should be concise.
* Must not include secrets, tokens, credentials, or full response bodies.

---

### `scope`

Type:

```text
object
```

Purpose:

Result from scope guard or related scope evaluation.

Example:

```json
{
  "target": "example.com",
  "hostname": "example.com",
  "in_scope": true,
  "reason": "Matched allowed domain",
  "allowed_scan_level": "passive_or_light"
}
```

Rules:

* Workflows with external requests must check scope before sending requests.
* Out-of-scope result must include scope metadata when available.
* Scope metadata must not be invented.

---

### `observations`

Type:

```text
array<object>
```

Purpose:

Structured non-sensitive observations produced by the workflow.

Examples:

```json
{
  "url": "https://example.com/",
  "status": "observed",
  "status_code": 200,
  "content_type": "text/html",
  "body_size": 1234,
  "headers_summary": {
    "content-type": "text/html",
    "content-length": "1234"
  }
}
```

Common observation statuses:

```text
observed
parsed
not_found
blocked
request_error
parse_error
unsupported_content_type
oversized
skipped_oversized
workflow_error
```

Rules:

* Observations must not contain full response bodies.
* Observations must not contain cookies.
* Observations must not contain authorization headers.
* Observations must not contain tokens, secrets, personal data, or payment data.
* Observations are not proof of vulnerability.

---

### `inventory_candidates`

Type:

```text
array<object>
```

Purpose:

Endpoint inventory candidates discovered by inventory workflows.

Example:

```json
{
  "target": "example.com",
  "url": "/api/users",
  "normalized_url": "https://example.com/api/users",
  "source": "javascript_static_analysis",
  "method_guess": "GET",
  "endpoint_type": "api",
  "priority": "medium",
  "confidence": "medium",
  "discovered_by": "safe_js_endpoint_extraction_workflow",
  "evidence": {
    "status_code": 200,
    "content_type": "application/javascript",
    "body_size": 50000,
    "headers_summary": {
      "content-type": "application/javascript"
    }
  },
  "validator_result": {},
  "recommended_next_skill": "",
  "recommended_next_steps": [],
  "notes": ""
}
```

Rules:

* Inventory candidates are not vulnerability proof.
* Inventory candidates must not trigger automatic exploitation.
* Evidence must be sanitized.
* Do not store full response bodies.
* Do not store cookies, credentials, tokens, secrets, personal data, or payment data.
* Use `tools/inventory_candidate_builder.py` when possible.

---

### `findings`

Type:

```text
array<object>
```

Purpose:

Optional list of finding-like objects returned in workflow output.

Current preferred behavior:

* Most workflows save observations or candidate findings through storage.
* Top-level `findings` may remain empty unless workflow explicitly needs to return finding objects.

Rules:

* Do not use `findings` to claim confirmed vulnerabilities unless controlled validation exists and evidence supports it.
* In v0.5, most outputs should remain observations or candidate findings.
* Confirmed finding status belongs to future controlled validation workflows.

---

### `errors`

Type:

```text
array<object|string>
```

Purpose:

Structured errors that did not necessarily stop the whole workflow.

Examples:

```json
[
  {
    "source": "http_probe",
    "error": "HTTP probe raised exception: timeout"
  }
]
```

Rules:

* Errors should be non-sensitive.
* Do not include raw exception data if it contains secrets.
* Request/helper failure should generally become `request_error`.
* Child workflow failure should generally become `workflow_error`.

---

### `warnings`

Type:

```text
array<object|string>
```

Purpose:

Non-fatal warnings.

Examples:

```json
[
  "Content-Type was empty; parsing allowed conservatively."
]
```

Rules:

* Warnings should not be used for vulnerabilities.
* Warnings should not contain secrets.

---

### `summary`

Type:

```text
object
```

Purpose:

Concise workflow-specific result summary.

Example:

```json
{
  "requests_sent": 1,
  "status": "completed",
  "max_requests": 1,
  "inventory_candidate_count": 3
}
```

Rules:

* Summary should be easy for the runtime AI agent to read.
* Include counts and limits.
* Include effective request budgets where relevant.
* Do not include sensitive data.
* Do not include full response bodies.

---

### `safety`

Type:

```text
object
```

Purpose:

Standard safety metadata.

Example:

```json
{
  "requests_sent": 1,
  "scan_level": "low-risk",
  "fuzzing": false,
  "bruteforce": false,
  "exploitation": false,
  "crawling": false,
  "credentialed_request": false,
  "state_changing": false
}
```

Required fields:

```text
requests_sent
scan_level
fuzzing
bruteforce
exploitation
crawling
credentialed_request
state_changing
```

Rules:

* Use `tools/safety_metadata.py`.
* Defaults must be safe.
* Do not under-report request count.
* If workflow crawls, set `crawling=true`.
* If workflow does not crawl, set `crawling=false`.
* v0.5 workflows must not set `fuzzing=true`, `bruteforce=true`, `exploitation=true`, `credentialed_request=true`, or `state_changing=true`.

---

## Recommended Helper Usage

Use these helpers where appropriate:

```text
tools.result_schema.build_workflow_result
tools.result_schema.build_blocked_result
tools.result_schema.append_observation
tools.result_schema.append_error
tools.safety_metadata.build_safety_metadata
tools.http_result_utils.base_http_observation
tools.http_result_utils.headers_summary
tools.http_result_utils.get_content_type
tools.http_result_utils.probe_body_text
tools.inventory_candidate_builder.build_validated_inventory_candidate
```

---

# Standard Result Types

## Successful Observation Result

Example:

```json
{
  "target": "https://example.com",
  "stopped": false,
  "reason": "",
  "scope": {
    "in_scope": true,
    "hostname": "example.com"
  },
  "observations": [
    {
      "url": "https://example.com",
      "status": "observed",
      "status_code": 200,
      "content_type": "text/html",
      "body_size": 1234,
      "headers_summary": {
        "content-type": "text/html"
      }
    }
  ],
  "inventory_candidates": [],
  "findings": [],
  "errors": [],
  "warnings": [],
  "summary": {
    "status": "completed",
    "requests_sent": 1,
    "max_requests": 1
  },
  "safety": {
    "requests_sent": 1,
    "scan_level": "low-risk",
    "fuzzing": false,
    "bruteforce": false,
    "exploitation": false,
    "crawling": false,
    "credentialed_request": false,
    "state_changing": false
  }
}
```

---

## Blocked Out-of-Scope Result

Example:

```json
{
  "target": "evil.test",
  "stopped": true,
  "reason": "Target is not in scope.",
  "scope": {
    "in_scope": false,
    "hostname": "evil.test",
    "reason": "Not in allowed scope"
  },
  "observations": [],
  "inventory_candidates": [],
  "findings": [],
  "errors": [],
  "warnings": [],
  "summary": {
    "status": "blocked",
    "requests_sent": 0
  },
  "safety": {
    "requests_sent": 0,
    "scan_level": "blocked",
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

* `requests_sent` must be 0.
* `stopped` must be true.
* No child workflow should run.
* No HTTP helper should be called.

---

## Request Error Result

Example:

```json
{
  "target": "https://example.com",
  "stopped": false,
  "reason": "HTTP probe failed.",
  "scope": {
    "in_scope": true,
    "hostname": "example.com"
  },
  "observations": [
    {
      "url": "https://example.com",
      "status": "request_error",
      "status_code": null,
      "content_type": "",
      "body_size": null,
      "headers_summary": {},
      "error": "HTTP probe raised exception: timeout"
    }
  ],
  "inventory_candidates": [],
  "findings": [],
  "errors": [
    "HTTP probe raised exception: timeout"
  ],
  "warnings": [],
  "summary": {
    "status": "error",
    "requests_sent": 1,
    "max_requests": 1
  },
  "safety": {
    "requests_sent": 1,
    "scan_level": "low-risk",
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

* If helper was attempted, count it.
* Do not crash on exceptions.
* Do not store sensitive data from exception messages.

---

## Inventory Result

Example:

```json
{
  "target": "example.com",
  "stopped": false,
  "reason": "",
  "scope": {
    "in_scope": true,
    "hostname": "example.com"
  },
  "observations": [
    {
      "url": "https://example.com/sitemap.xml",
      "status": "parsed",
      "status_code": 200,
      "content_type": "application/xml",
      "body_size": 5000,
      "headers_summary": {
        "content-type": "application/xml"
      },
      "extracted_url_count": 2
    }
  ],
  "inventory_candidates": [
    {
      "target": "example.com",
      "url": "https://example.com/login",
      "normalized_url": "https://example.com/login",
      "source": "sitemap",
      "method_guess": "GET",
      "endpoint_type": "auth_page",
      "priority": "medium",
      "confidence": "medium",
      "discovered_by": "safe_sitemap_parser_workflow",
      "evidence": {
        "status_code": 200,
        "content_type": "application/xml",
        "body_size": 5000,
        "headers_summary": {
          "content-type": "application/xml"
        }
      },
      "validator_result": {},
      "recommended_next_skill": "",
      "recommended_next_steps": [],
      "notes": "URL extracted from sitemap XML only. The workflow did not request this extracted URL."
    }
  ],
  "findings": [],
  "errors": [],
  "warnings": [],
  "summary": {
    "inventory_candidate_count": 1,
    "extracted_url_count": 2,
    "skipped_url_count": 0
  },
  "safety": {
    "requests_sent": 1,
    "scan_level": "low-risk",
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

* Extracted URLs must not be automatically requested unless the workflow explicitly allows bounded crawling.
* Sitemap parser must not request sitemap-listed URLs.
* JS extraction must not request API endpoints extracted from JS.
* Inventory is not proof of vulnerability.

---

# Safety Requirements

## Sensitive Data Must Not Be Stored

Never store:

```text
set-cookie
cookie
authorization
proxy-authorization
x-api-key
api-key
token
secret
session
personal_data
payment_data
full response body
raw sensitive HTML
raw sensitive JSON
credential material
```

## Allowed Safe Metadata

Generally safe metadata:

```text
status_code
content_type
body_size
content_length
final_url
redirect_count
safe redirect history
safe headers summary
missing security headers
present recommended security headers
CORS headers after sanitization
source
discovered_from
method_guess
```

## Full Body Handling

Rules:

* Workflows may inspect response text in memory if needed for parsing.
* Workflows must not persist full response text.
* Observations must not include full body.
* Saved findings must not include full body.
* Evidence should use summary fields.

---

# Workflow-Specific Notes

## HTTP Probe Workflow

Expected safety:

```text
scan_level=low-risk
requests_sent<=1
crawling=false
```

Must not store full body or sensitive headers.

---

## Security Headers Workflow

Expected safety:

```text
scan_level=low-risk
requests_sent<=1
crawling=false
```

Must only store safe security header metadata.

---

## CORS Observation Workflow

Expected safety:

```text
scan_level=low-risk
requests_sent<=1
crawling=false
credentialed_request=false
```

Must use harmless test origin.

Credential-like test origins must be replaced.

---

## Passive Recon Workflow

Expected safety:

```text
scan_level=low-risk
requests_sent<=3
crawling=false
```

Should aggregate child workflow summaries only after sanitization.

---

## Robots / Security.txt Workflow

Expected safety:

```text
scan_level=low-risk
requests_sent<=3
crawling=false
```

Must not request robots `Disallow` paths.

---

## Sitemap Parser Workflow

Expected safety:

```text
scan_level=low-risk
requests_sent<=1
crawling=false
```

Must not request URLs listed in sitemap.

---

## JS Endpoint Extraction Workflow

Expected safety:

```text
scan_level=medium-risk
requests_sent<=31
crawling=false
```

Must not:

* Execute JavaScript.
* Evaluate JavaScript.
* Request API endpoints extracted from JavaScript.
* Fuzz or exploit.

---

## Bounded Crawl Workflow

Expected safety:

```text
scan_level=medium-risk
requests_sent<=30
crawling=true
```

Must not:

* Download JavaScript.
* Submit forms.
* Request JS-extracted API endpoints.
* Leave scope.
* Exceed max depth.
* Exceed max pages.
* Exceed max requests.

---

# Codex Instructions

When generating or refactoring workflow output, Codex should:

1. Preserve existing backward-compatible fields.
2. Add standard schema fields where missing.
3. Use shared helpers where possible.
4. Never remove safety metadata.
5. Never under-report request count.
6. Never store full response bodies.
7. Never store sensitive headers.
8. Never claim vulnerability confirmation unless a future controlled-validation workflow explicitly supports it.
9. Add or update tests when result shape changes.
10. Keep LM Studio MCP tool names stable.

---

# Anti-Patterns

Do not return workflow results like this:

```json
{
  "status": "ok",
  "data": "<full html body here>"
}
```

Problems:

* Missing scope metadata.
* Missing safety metadata.
* Missing request count.
* Stores full body.
* Not compatible with runtime agent.

Do not return inventory results like this:

```json
{
  "url": "https://example.com/api/users",
  "vulnerable": true
}
```

Problems:

* Inventory is not validation.
* No evidence.
* No safety metadata.
* Unsupported vulnerability claim.

Do not return error results like this:

```json
{
  "error": "failed"
}
```

Problems:

* Missing target.
* Missing scope.
* Missing observations.
* Missing safety metadata.
* Missing request count.

---

# Minimum Acceptable Workflow Result

A minimal acceptable result:

```json
{
  "target": "example.com",
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
