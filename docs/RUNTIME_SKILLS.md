# Runtime Skills

本文說明 v0.3-runtime-skills-and-skill-loader 的 runtime skill 設計、使用邊界與安全規則。

## Skill 分層

### `skills/agent_runtime`

`skills/agent_runtime` 是給未來 runtime AI agent 使用的本機 Markdown 知識層。

Runtime skills 用來協助 agent 做判斷，而不是直接執行動作。它們描述：

- 何時使用某個 skill。
- 執行前需要確認的 preconditions。
- 允許與禁止的行為。
- Evidence 要求。
- Validation rules。
- False positive rules。
- Escalation rules。
- Output schema。

這些 skills 服務於未來 agent planner / runtime agent 的決策品質，例如分類、證據整理、false-positive 降低、manual validation 判斷、reporting decision 與 risk escalation。

### `skills/codex_dev`

`skills/codex_dev` 是給 Codex 維護專案使用的開發知識層。

Codex development skills 可用來說明如何維護架構、撰寫測試、更新文件、開發 workflow 或保持 `server.py` thin wrapper。它們不是 runtime AI penetration testing agent 的任務知識來源。

## Skill Loader 邊界

`tools/skill_loader.py` 只負責讀取本機 Markdown 檔案：

```text
skills/agent_runtime/<skill_name>/SKILL.md
```

Skill loader 只回傳文字與安全 metadata。它不會：

- 執行 `SKILL.md` 內容。
- 執行 Python code。
- 執行 MCP tool。
- 呼叫 workflow。
- 發送 HTTP request。
- 發送任何外部 request。
- 修改 findings、logs、config 或 target state。

Skill loader 也必須拒絕 path traversal、絕對路徑，以及任何會逃出 `skills/agent_runtime` 的路徑。

## Runtime Skill 標準格式

每個 runtime `SKILL.md` 必須包含以下章節：

```text
# Skill Name

## Purpose

## When to Use

## Preconditions

## Allowed Actions

## Disallowed Actions

## Required Evidence

## Validation Rules

## False Positive Rules

## Escalation Rules

## Output Schema
```

## 安全邊界

Runtime skills 不是 exploit cookbook，也不是 payload cookbook。它們只能提供判斷準則、evidence 要求、false positive 規則與 escalation 規則。

Runtime skills 不得包含：

- Exploit payload。
- Brute force 指令。
- Credential attack 指令。
- Destructive action。
- Real data exfiltration 指令。
- Unrestricted exploit chaining。

Runtime skills 不得要求 AI 自動讀取或保存 cookie、token、secret、personal data、payment data 或完整敏感 response body。

若任何後續 validation 需要 medium/high risk action，必須先通過 `risk_gate` 與 explicit approval。若 target 不在 scope 內，必須停止。

## v0.3 範圍

v0.3 不新增 vulnerability workflow。

v0.3 不新增 exploit logic、fuzzing、bruteforce、credential testing、destructive validation 或 state-changing validation。

v0.3 已包含：

- `tools/skill_loader.py`
- `tests/test_skill_loader.py`
- `skills/agent_runtime/passive_recon/SKILL.md`
- `skills/agent_runtime/security_headers/SKILL.md`
- `skills/agent_runtime/cors/SKILL.md`
- `skills/agent_runtime/reporting/SKILL.md`
- `skills/agent_runtime/risk_gate/SKILL.md`

## 後續方向

v0.4 才會進入 attack surface inventory 方向，例如安全的 robots/security.txt/sitemap 或 JS endpoint inventory 類工作。

v0.4 仍必須遵守：

- Scope guard。
- Risk gate。
- Approval controller。
- Tool risk profiles。
- Workflow safety metadata。
- 不保存敏感資料。
- 不新增 unrestricted exploit、bruteforce、credential attack 或 destructive action。
