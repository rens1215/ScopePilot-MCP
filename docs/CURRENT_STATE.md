# Current State

Current version: v0.1-safe-passive-recon

Completed:
- safe_http_probe_workflow
- safe_security_headers_workflow
- safe_cors_observation_workflow
- safe_passive_recon_workflow
- endpoint_classifier
- priority_scorer
- finding_summarizer

Next milestone:
v0.2-risk-gate-and-execution-policy

Next files to implement:
- agent/risk_gate.py
- agent/approval_controller.py
- tools/policy_loader.py
- config/tool_risk_profiles.json
- tests/test_risk_gate.py

Do not add new vulnerability workflows before v0.2 is complete.