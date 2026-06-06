# Security Headers Runtime Skill

## Purpose

協助未來 runtime AI agent 解讀 security headers observation，並以保守方式判斷是否形成 observation、candidate finding 或需要人工驗證。本 skill 不提供 payload，不執行測試，也不替代 validator。

## When to Use

- 已取得 in-scope target 的 security headers workflow 結果。
- 需要判斷缺少 CSP、X-Frame-Options、HSTS 或其他 headers 是否值得報告。
- 需要撰寫 evidence summary、false-positive notes 或下一步建議。

## Preconditions

- Target 必須已通過 scope check；若 target 不在 scope 內，必須立即停止。
- Header observation 必須來自 safe/low-risk workflow，且 workflow safety metadata 可用。
- 若需要 medium/high risk validation，必須先通過 risk_gate 與 explicit approval。
- 不得保存 cookie、token、secret、personal data、payment data 或完整敏感 response body。

## Allowed Actions

- 檢視 response header metadata 與 validator result。
- 保守評估缺少 security header 的 context 與影響。
- 依據 endpoint classification 調整優先級，例如 login、admin、interactive app 可能比 static asset 更重要。
- 建議人工驗證或後續低風險確認。

## Disallowed Actions

- 不得注入 payload、嘗試 clickjacking exploitation、XSS exploitation 或 browser-based exploit。
- 不得嘗試繞過 CSP 或建立攻擊頁面。
- 不得進行 credential testing、bruteforce、DoS 或 destructive action。
- 不得把缺少單一 header 直接宣稱為 confirmed high impact。

## Required Evidence

- Target、final URL、status code。
- Observed response headers 的安全摘要。
- Missing or weak header list。
- Endpoint classification、severity、confidence。
- Validator reason 與 false-positive notes。

## Validation Rules

- 缺少 header 通常是 observation 或 low-risk candidate，除非有具體且授權的 impact evidence。
- Static asset、redirect response、error page 或 CDN-generated response 應降低信心。
- HSTS 僅適用 HTTPS context；HTTP-only 或 redirect-only evidence 不應過度推論。
- CSP 缺失不等於 XSS；必須避免未授權 exploitation。

## False Positive Rules

- 某些 API endpoint 不需要與 browser UI 相同的 headers。
- CDN、reverse proxy 或 framework default page 可能影響 header 結果。
- Missing X-Frame-Options 在已有適當 CSP frame-ancestors 時可能不是問題。
- Header 存在但格式錯誤時，需由 validator 或人工確認。

## Escalation Rules

- 若需要證明 clickjacking、XSS、account impact 或 authenticated behavior，必須通過 risk_gate 與 explicit approval。
- 若需要使用帳號、credential 或狀態敏感互動，視為 high-risk validation。
- 若 target 不在 scope 內，必須停止。

## Output Schema

```json
{
  "skill": "security_headers",
  "target": "",
  "headers_observed": {},
  "missing_headers": [],
  "validator_result": {},
  "status": "observation | candidate_finding | needs_manual_validation",
  "severity": "info | low | medium | high",
  "confidence": "low | medium | high",
  "false_positive_notes": [],
  "recommended_next_steps": []
}
```
