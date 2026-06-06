# Risk Gate Runtime Skill

## Purpose

協助未來 runtime AI agent 理解工具風險政策、approval 條件與 fail-closed 原則。此 skill 只提供 policy evaluation 的判斷準則；risk_gate 本身不執行 tool、不呼叫 workflow、不發送 request。

## When to Use

- 在選擇 MCP tool 或 workflow 前，需要判斷 risk level、approval requirement 與 allowed mode。
- 需要處理 unknown、blocked、malformed profile 或 missing profile。
- 需要建立 approval request 或向使用者說明為何某 action 被拒絕。

## Preconditions

- Target 必須先確認是否在 scope 內；若 target 不在 scope 內，必須停止。
- Tool 必須存在於 `config/tool_risk_profiles.json`，否則視為 unknown 並 deny by default。
- Medium/high risk validation 必須通過 risk_gate 與 explicit approval。
- 不得保存 cookie、token、secret、personal data、payment data 或完整敏感 response body。

## Allowed Actions

- 評估 tool_name、risk_level、allowed_modes、external_requests、max_requests、changes_state、uses_credentials。
- 產生 allowed、requires_approval、reason、risk_level、profile 等 policy decision。
- 建立 approval_request object，供使用者審核。
- 對 unknown、blocked、malformed profile 採 fail-closed deny。

## Disallowed Actions

- 不得執行被評估的 tool。
- 不得呼叫 workflow。
- 不得發送 HTTP request 或任何外部 request。
- 不得繞過 scope_guard、risk_gate、approval_controller 或 tool_risk_profiles。
- 不得新增 exploit、fuzzing、bruteforce、credential testing 或 destructive action。

## Required Evidence

- Tool name。
- Target 或 target=null。
- Execution mode，例如 authorized 或 lab。
- User approval 狀態。
- Loaded risk profile 或 missing/malformed profile 訊號。
- Risk evaluation reason。

## Validation Rules

- Safe tool 可 allowed=true，且不需 approval。
- Low、medium、high tool 若 user_approved=false，必須 allowed=false 且 requires_approval=true。
- Low、medium、high tool 只有在 user_approved=true 且 mode 在 allowed_modes 內時才可 allowed=true。
- Blocked tool 必須 deny，即使 user_approved=true。
- Unknown tool、missing profile、malformed profile 必須 deny by default。

## False Positive Rules

- Tool 名稱相似不代表同一工具；必須精確匹配 profile。
- 空 policy 不代表全部允許，而是沒有工具被確認允許。
- Approval request object 不代表已執行，也不代表已授權所有後續行為。
- Safe risk evaluation 不代表被評估的目標 workflow 也是 safe；必須看被評估 tool 的 profile。

## Escalation Rules

- 若 action 是 medium/high risk，必須要求 explicit approval。
- 若 action 需要 credential、帳號、敏感資料或狀態改變，應視為 high-risk 並要求更嚴格審核。
- 若 target 不在 scope 內，必須停止，不得評估成可執行。
- 若 profile 缺失或格式錯誤，必須 fail closed。

## Output Schema

```json
{
  "skill": "risk_gate",
  "risk_evaluation": {
    "allowed": false,
    "requires_approval": false,
    "reason": "",
    "risk_level": "safe | low | medium | high | blocked | unknown",
    "profile": {}
  },
  "approval_request": {
    "approval_required": false,
    "tool_name": "",
    "target": "",
    "risk_level": "",
    "reason": "",
    "estimated_requests": 0,
    "external_requests": false,
    "changes_state": false,
    "uses_credentials": false,
    "allowed_modes": [],
    "safety_summary": {}
  }
}
```
