# Passive Recon Runtime Skill

## Purpose

協助未來 runtime AI agent 判斷何時進行低風險 passive recon，並定義 evidence、false positive 與 escalation 規則。本 skill 只提供判斷準則，不是 exploit 腳本，也不是攻擊手冊。

## When to Use

- 使用者要求對明確授權目標做初步 reconnaissance。
- 需要整理 HTTP probe、security headers 與 CORS observation 的低風險結果。
- 需要產生下一步建議，但尚未進入 medium/high risk validation。

## Preconditions

- Target 必須已通過 scope check；若 target 不在 scope 內，必須立即停止。
- 執行任何 external-request workflow 前，必須符合 risk profile、risk_gate 與 approval 規則。
- 只允許使用已暴露、已分類、已授權的 safe 或 low-risk workflow。
- 不得保存 cookie、token、secret、personal data、payment data 或完整敏感 response body。

## Allowed Actions

- 讀取已授權、低風險 workflow 的摘要結果。
- 彙整狀態碼、最終 URL、redirect summary、header metadata、body size、endpoint classification 等非敏感 metadata。
- 標記 observation、candidate finding 或 needs manual validation。
- 建議下一步是否需要人工審核或 risk_gate approval。

## Disallowed Actions

- 不得執行 exploit、fuzzing、bruteforce、credential testing、DoS 或 destructive action。
- 不得自動擴大掃描範圍或進行 crawling。
- 不得嘗試繞過 auth、存取未授權資料或串接漏洞利用。
- 不得保存敏感內容、完整 response body 或任何憑證資料。

## Required Evidence

- Target 與 scope result。
- Workflow 名稱與 safety metadata，包含 requests_sent。
- HTTP status、final URL、redirect summary、selected headers summary、body size。
- Endpoint classification 與 confidence。
- 任何 finding 判斷都必須附上 reason 與 false-positive notes。

## Validation Rules

- Passive recon 結果通常只能支持 observation 或 candidate finding，不應直接宣稱 confirmed impact。
- 若 evidence 只顯示一般服務可連線，應標記為 observation。
- 若結果涉及 auth、access control、敏感資料或狀態改變，必須停止自動化並要求 medium/high risk validation。

## False Positive Rules

- Redirect、missing headers 或公開頁面不必然代表漏洞。
- Error page、CDN/WAF response 或 generic landing page 不應過度推論。
- Body size 或 title 只能作為輔助訊號，不能單獨證明安全問題。

## Escalation Rules

- 任何需要多步驗證、帳號、credential、敏感資料比對或狀態改變的情境，都必須通過 risk_gate 與 explicit approval。
- Medium/high risk validation 未獲 approval 前，不得執行。
- 若 target 不在 scope 內，必須停止，不得嘗試替代目標或相近網域。

## Output Schema

```json
{
  "skill": "passive_recon",
  "target": "",
  "scope": {},
  "summary": {},
  "evidence": {
    "requests_sent": 0,
    "http_metadata": {},
    "endpoint_classification": {}
  },
  "status": "observation | candidate_finding | needs_manual_validation",
  "confidence": "low | medium | high",
  "false_positive_notes": [],
  "recommended_next_steps": []
}
```
