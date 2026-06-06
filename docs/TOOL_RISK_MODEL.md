# 工具風險模型

本文說明 v0.2-risk-gate-and-execution-policy 的工具風險模型。此版本的重點是建立工具執行前的政策判斷與 approval request 結構，不新增任何 vulnerability workflow。

## 風險等級

### safe

`safe` 代表不會發送外部 request、通常只處理本機資料或政策判斷的工具。這類工具可由 `risk_gate` 直接允許，不需要 user approval。

範例：

- scope check
- finding summarization
- report draft generation
- risk evaluation

### low

`low` 代表會發送有限、非破壞性的外部 request，且用途是低風險觀察或安全 metadata 收集。即使風險較低，這類工具仍會接觸目標系統，因此預設需要 user approval。

範例：

- safe HTTP probe
- security headers observation
- CORS observation
- passive recon workflow

### medium

`medium` 代表較具針對性的驗證、可能涉及多個 request，或會更接近具體安全假設的觀察。v0.2 目前沒有 exposed medium-risk tool；未來若加入，必須先加入 `config/tool_risk_profiles.json`，並通過 `risk_gate` 與 explicit approval。

### high

`high` 代表敏感驗證，例如需要 credential、受控帳號、授權情境或狀態敏感操作的測試。v0.2 目前沒有 exposed high-risk tool；未來若加入，必須先加入 `config/tool_risk_profiles.json`，並要求 explicit approval 與更嚴格的 request/evidence 控制。

### blocked

`blocked` 代表不得自動化執行的行為。即使使用者提供 approval，`risk_gate` 也必須 deny。

範例：

- brute force
- credential stuffing
- DoS 或 stress testing
- mass fuzzing
- destructive action
- unrestricted exploit chaining
- unauthorized access attempt
- real data exfiltration

### unknown

`unknown` 代表工具不存在於 policy、缺少 profile、或風險無法被可靠判斷。unknown tools 一律 deny by default。

## 目前 exposed MCP tools

目前 `config/tool_risk_profiles.json` 定義的 exposed MCP tools 如下：

| Tool | Risk level | External requests | Max requests | Default approval |
| --- | --- | --- | --- | --- |
| `tool_check_scope` | `safe` | false | 0 | 不需要 |
| `tool_safe_http_probe_workflow` | `low` | true | 1 | 需要 |
| `tool_safe_security_headers_workflow` | `low` | true | 1 | 需要 |
| `tool_safe_cors_observation_workflow` | `low` | true | 1 | 需要 |
| `tool_safe_passive_recon_workflow` | `low` | true | 3 | 需要 |
| `tool_summarize_findings` | `safe` | false | 0 | 不需要 |
| `tool_write_report_draft` | `safe` | false | 0 | 不需要 |

所有目前 exposed MCP tools 的 `allowed_modes` 都包含：

- `authorized`
- `lab`

## Approval 規則

`low`、`medium`、`high` 工具都需要 user approval，原因是它們可能會接觸外部目標、增加 request 數量、使用更具針對性的驗證方式，或涉及更敏感的測試情境。

`risk_gate` 的目前規則：

- `safe` tool 可以 `allowed=true`，且 `requires_approval=false`。
- `low`、`medium`、`high` tool 在 `user_approved=false` 時必須 deny，且 `requires_approval=true`。
- `low`、`medium`、`high` tool 只有在 `user_approved=true` 且 `mode` 存在於 `allowed_modes` 內時，才可 `allowed=true`。
- disallowed mode 必須 deny。
- `blocked` tool 必須 deny。
- `unknown` tool 必須 deny by default。

## Fail-closed 設計

v0.2 採用 fail-closed policy：

- unknown tool deny by default。
- missing profile deny by default。
- malformed profile deny by default。
- config 缺失、JSON 格式錯誤、或 top-level 不是 object 時，policy loader 回傳空 dict。
- 空 policy 不代表允許所有工具，而是代表沒有任何工具可被 policy 確認，因此 risk gate 會 deny。

profile 若缺少必要欄位或欄位型別錯誤，也必須 deny。這避免壞掉的 config 讓 MCP server crash，或讓不完整政策被誤解為允許執行。

## Risk Gate 邊界

`agent/risk_gate.py` 只負責評估 tool action 是否符合風險政策。

它不會：

- 執行任何 MCP tool
- 呼叫任何 workflow
- 發送 HTTP request
- 發送任何外部 request
- 修改 workflow 行為
- 繞過 scope guard
- 新增 vulnerability workflow

`risk_gate` 的輸出是政策判斷結果，至少包含：

- `allowed`
- `requires_approval`
- `reason`
- `risk_level`
- `profile`

## Approval Controller 邊界

`agent/approval_controller.py` 只負責根據 risk evaluation 建立 `approval_request` object。

它不會：

- 執行任何 MCP tool
- 呼叫任何 workflow
- 發送 HTTP request
- 發送任何外部 request
- 決定新的工具是否應被允許

`approval_controller` 只是把 risk evaluation 和 profile metadata 整理成可供使用者審核的 approval request。allow/deny 的來源仍是 `risk_gate`。

approval request 至少包含：

- `approval_required`
- `tool_name`
- `target`
- `risk_level`
- `reason`
- `estimated_requests`
- `external_requests`
- `changes_state`
- `uses_credentials`
- `allowed_modes`
- `safety_summary`

## v0.2 範圍限制

v0.2 不新增任何 vulnerability workflow，也不改變既有 workflow 行為。

後續若要新增 workflow，必須先：

1. 在 `config/tool_risk_profiles.json` 加入對應 tool profile。
2. 明確標示 `risk_level`、`external_requests`、`default_requires_approval`、`max_requests`、`changes_state`、`uses_credentials`、`allowed_modes`。
3. 確認該 workflow 仍遵守 scope validation、request limit、logging、safety metadata 與敏感資料保護規則。
4. 讓 medium/high risk validation 通過 `risk_gate` 與 explicit approval。
