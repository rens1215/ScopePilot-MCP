# CORS Runtime Skill

## Purpose

協助未來 runtime AI agent 解讀 CORS observation，並避免把單次 header observation 過度推論為 confirmed vulnerability。本 skill 提供判斷準則，不提供 exploit payload 或 credential-based 測試流程。

## When to Use

- 已取得 in-scope target 的 safe CORS observation workflow 結果。
- 需要判斷 reflected Origin、wildcard Origin、credentials header 或缺少 CORS header 的意義。
- 需要產生 candidate finding、false-positive notes 或 escalation 建議。

## Preconditions

- Target 必須已通過 scope check；若 target 不在 scope 內，必須立即停止。
- CORS observation 必須使用 harmless Origin，且不含 cookie、token 或 credential。
- 若需要確認 real data access、credentialed request 或 authenticated impact，必須通過 risk_gate 與 explicit approval。
- 不得保存 cookie、token、secret、personal data、payment data 或完整敏感 response body。

## Allowed Actions

- 觀察 Access-Control-Allow-Origin、Access-Control-Allow-Credentials 與相關 CORS headers。
- 將結果分類為 observation、candidate finding 或 needs manual validation。
- 記錄 non-sensitive metadata，例如 status code、header summary、test_origin。
- 建議是否需要人工或授權帳號情境驗證。

## Disallowed Actions

- 不得發送 credentialed request，除非已通過 high-risk approval 且有明確授權。
- 不得嘗試讀取、保存或 exfiltrate 使用者資料。
- 不得進行 exploit chaining、bruteforce、credential stuffing、DoS 或 destructive action。
- 不得把 reflected Origin 單獨視為 confirmed data exposure。

## Required Evidence

- Target、test_origin、status code。
- Access-Control-Allow-Origin 與 Access-Control-Allow-Credentials 的 observed values。
- 是否有 sensitive endpoint classification。
- Validator result、reason、confidence、false-positive notes。
- Safety metadata，包含 requests_sent 與 credentialed_request=false。

## Validation Rules

- ACAO 反射 Origin 加上 credentials=true 可能是 candidate finding，但仍需確認是否能存取敏感資料。
- Wildcard ACAO 在無 credentials 且 public data context 下通常較低風險。
- 沒有 CORS headers 通常不是漏洞。
- 任何 authenticated impact 都需要 explicit approval，不能由 runtime agent 自行假設。

## False Positive Rules

- Public API、static asset 或 intentionally public resource 可能允許寬鬆 CORS。
- Browser enforcement、preflight behavior 與 response type 可能影響可利用性。
- 單一 response header observation 不足以證明資料外洩。
- Error page 或 CDN response 可能造成誤判。

## Escalation Rules

- 需要 credential、controlled account、sensitive data validation 或 cross-origin data read proof 時，必須通過 risk_gate 與 explicit approval。
- 若 validation 可能存取 personal data、payment data 或 secret，應停止並要求人工審核。
- 若 target 不在 scope 內，必須停止。

## Output Schema

```json
{
  "skill": "cors",
  "target": "",
  "test_origin": "",
  "cors_headers": {},
  "validator_result": {},
  "status": "observation | candidate_finding | needs_manual_validation",
  "severity": "info | low | medium | high",
  "confidence": "low | medium | high",
  "false_positive_notes": [],
  "recommended_next_steps": []
}
```
