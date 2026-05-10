# MCP Bug Bounty Agent Architecture

## Goal

This project is an AI-assisted bug bounty research copilot. It performs low-risk, scoped reconnaissance and helps organize findings for manual review.

## Layers

- `server.py`: MCP tool registration only.
- `tools/`: low-level reusable utilities.
- `validators/`: false-positive-aware validation logic.
- `workflows/`: safe multi-step workflows.
- `config/`: scope, scan policy, false positive rules.
- `data/`: logs and findings.

## Safety Rules

- Every workflow must call `check_scope()` first.
- Every workflow must log start, scope result, request count, save result, and completion.
- No workflow may fuzz, brute force, crawl, exploit, or use credentials unless explicitly designed and reviewed.
- All external-request workflows must report `requests_sent`.