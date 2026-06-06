# Reporting Runtime Skill

## Purpose

協助未來 runtime AI agent 將已授權、已驗證或需要人工驗證的 observations/candidate findings 整理成清楚的 report draft。Report draft 不等於自動提交，也不得替代人工確認。

## When to Use

- 需要整理 finding summary、evidence summary、impact、reproduction steps 與 recommendation。
- 需要將 validator result、priority score 與 false-positive notes 轉成可讀報告草稿。
- 需要標示 validation status，例如 observation、candidate_finding、needs_manual_validation 或 confirmed_finding。

## Preconditions

- Target 必須已通過 scope check；若 target 不在 scope 內，必須停止並不得產生提交建議。
- Evidence 必須來自允許的 workflow、validator 或人工提供資料。
- 若 report 依賴 medium/high risk validation，該 validation 必須已通過 risk_gate 與 explicit approval。
- 不得保存 cookie、token、secret、personal data、payment data 或完整敏感 response body。

## Allowed Actions

- 產生 report draft、summary、recommended remediation 與 validation status。
- 使用非敏感 metadata、摘要、hash、headers summary 或 reproducible steps。
- 標註 evidence limitation、false-positive notes 與需要人工確認的地方。
- 清楚區分 observation、candidate finding 與 confirmed finding。

## Disallowed Actions

- 不得自動提交 report 到任何平台。
- 不得偽稱未驗證 finding 已 confirmed。
- 不得包含 exploit payload cookbook、credential attack 指令或 destructive steps。
- 不得保存或輸出敏感資料、完整 response body、cookie、token 或 secret。

## Required Evidence

- Target、scope result、finding type、severity、confidence。
- Validator result 或 manual validation status。
- Reproducible but safe steps，避免 destructive 或 unauthorized action。
- Evidence summary 與 false-positive notes。
- Impact statement 與 recommendation。

## Validation Rules

- Report draft 必須明確標示 validation status。
- 未經 manual validation 的 candidate 不應使用 confirmed wording。
- Impact 必須由 evidence 支持，不能基於猜測誇大。
- 若 evidence 不足，應輸出 needs_manual_validation。

## False Positive Rules

- Missing header、CORS observation 或 endpoint metadata 不必然代表可利用漏洞。
- Public data、static asset、error page 或 CDN behavior 可能降低 reportability。
- 若無法重現，應在 report draft 中明確標示限制。
- 若 impact 需要帳號或敏感資料驗證，需等待 approved validation。

## Escalation Rules

- 若需要補充 medium/high risk validation 才能完成 report，必須先通過 risk_gate 與 explicit approval。
- 若 target 不在 scope 內，必須停止，不得撰寫鼓勵提交的報告。
- 若 evidence 涉及敏感資料，應改用摘要、hash 或人工審核，而不是保存原文。

## Output Schema

```json
{
  "skill": "reporting",
  "title": "",
  "target": "",
  "validation_status": "observation | candidate_finding | needs_manual_validation | confirmed_finding",
  "severity": "info | low | medium | high | critical",
  "confidence": "low | medium | high",
  "summary": "",
  "evidence_summary": "",
  "steps_to_reproduce": [],
  "impact": "",
  "recommendation": "",
  "false_positive_notes": [],
  "submission_ready": false
}
```
