# Attack Surface Inventory

本文說明 v0.4-attack-surface-inventory 的 Step 1：Inventory foundation。

## 目的

Attack surface inventory 的目的是建立目標公開入口點的安全、結構化地圖，協助未來 runtime AI agent 在更深層驗證前先理解：

- 有哪些 endpoint 或 URL candidate。
- 每個 endpoint 來自哪個 discovery source。
- Endpoint 可能是 API、auth page、admin candidate、static asset、documentation、frontend 或 unknown。
- 哪些 endpoint 值得後續 controlled validation。
- 哪些 endpoint 可能只是低價值或高噪音項目。

Inventory 不是漏洞證明，也不代表 endpoint 可被利用。

## v0.4 Step 1 範圍

Step 1 只做 in-memory inventory foundation：

- URL normalization。
- Inventory item 建立。
- Inventory item 去重。
- Endpoint type 與 priority 的保守分類。
- 本機 summary aggregation。

Step 1 不會：

- 發送 HTTP request。
- 呼叫 workflow。
- 新增 MCP tool。
- 新增 vulnerability workflow。
- 寫入 `data/`。
- 執行 exploit、fuzzing、bruteforce、credential testing、DoS 或 destructive action。

## URL Normalization 規則

`tools/url_normalizer.py` 負責將 URL 字串正規化成可用於 inventory 去重的格式。

目前規則：

- 支援 absolute HTTP/HTTPS URL。
- 支援 `base_url` 加 relative path。
- 移除 fragment，例如 `#section`。
- 正規化 scheme 與 hostname 大小寫。
- 保留 path 與 query。
- 拒絕 unsupported scheme，例如 `javascript:`、`data:`、`file:`、`ftp:`。
- 拒絕 URL credentials，避免將 username/password 帶入 inventory metadata。
- 回傳 dict，不將 parse error raise 給 caller。

URL normalizer 只做本機字串解析，不發送 request。

## Endpoint Inventory Schema

`tools/endpoint_inventory.py` 建立的 inventory item 以 `docs/ARCHITECTURE.md` 的 Endpoint Inventory Data Model 為基準。

建議 schema：

```json
{
  "target": "",
  "url": "",
  "normalized_url": "",
  "source": "robots | security_txt | sitemap | html_script_tag | javascript_static_analysis | manual",
  "method_guess": "GET",
  "endpoint_type": "frontend | api | auth_page | admin_candidate | static_asset | documentation | unknown",
  "priority": "low | medium | high",
  "confidence": "low | medium | high",
  "discovered_by": "",
  "evidence": {
    "status_code": null,
    "content_type": "",
    "body_size": null,
    "headers_summary": {}
  },
  "safety": {
    "requests_sent": 0,
    "fuzzing": false,
    "bruteforce": false,
    "exploitation": false,
    "crawling": false,
    "credentialed_request": false
  },
  "recommended_next_skill": "",
  "recommended_next_steps": [],
  "notes": ""
}
```

Step 1 只在記憶體中建立與處理這些 dict，不保存到 `data/`。

## Endpoint Type 與 Priority

`validators/inventory_validator.py` 只做保守分類與降噪，不做漏洞確認。

目前 endpoint type 分類：

- `api`: path 或 hostname 顯示 API 特徵，例如 `/api/`。
- `auth_page`: path 顯示 login、signin、auth、oauth、sso 等特徵。
- `admin_candidate`: path 顯示 admin、dashboard、console、manage 等特徵。
- `static_asset`: 常見靜態資產，例如 `.js`、`.css`、image、font、map。
- `documentation`: docs、swagger、openapi、redoc 等文件型 endpoint。
- `frontend`: 看起來像一般 frontend route 或頁面。
- `unknown`: 沒有足夠訊號時的保守分類。

Priority 原則：

- `auth_page`、`admin_candidate` 通常較高，因為後續可能需要受控驗證與 approval。
- `api` 通常中等或較高，因為可能是後續 inventory 或 validation 的重要入口。
- `documentation` 可能有助於理解 attack surface，但不代表漏洞。
- `static_asset` 通常較低，主要用於支援 JS extraction 或 frontend mapping。
- `unknown` 預設低 priority。

所有分類都只是 triage 訊號，不是 vulnerability finding。

## 敏感資料規則

Inventory 不得保存：

- Cookie。
- Token。
- Secret。
- Personal data。
- Payment data。
- 完整敏感 response body。
- Credential material。

Evidence 應偏向 metadata，例如 status code、content type、body size、headers summary、normalized URL、discovery source。

## 後續使用方式

後續 v0.4 robots/security.txt/sitemap/JS extraction/bounded crawler workflow 會使用這些 foundation 工具：

- Public metadata workflow 可將 robots/security.txt/sitemap references 正規化後放入 inventory。
- Sitemap workflow 可將 sitemap URLs 正規化、去重並建立 inventory items。
- JS extraction workflow 可從 JavaScript 文字中提取 candidate routes，但仍不得執行 JavaScript，也不得請求從 JS 中提取出的 API endpoint。
- Bounded crawler workflow 可收集同 scope HTML links、script `src`、sitemap links 與 same-scope frontend routes，用於建立 endpoint inventory。

Crawler 的目的只是建立 endpoint inventory，不是漏洞驗證。

## JS Endpoint Extraction Request Budget

`safe_js_endpoint_extraction_workflow` 適合大型 bug bounty domain 的前端 JavaScript endpoint discovery，因此允許較高但仍有硬上限的 request budget。

此 workflow 的限制：

- 預設最多請求 20 個 same-host 或 in-scope JavaScript files。
- 即使呼叫端要求更多，也最多請求 30 個 JavaScript files。
- 總 request 硬上限為 31，也就是 1 個 target HTML request 加最多 30 個 JS requests。
- `risk_level=medium`，必須通過 `risk_gate` 與 explicit approval。
- 這不是 crawler，不會遞迴追蹤頁面連結。
- 只會請求 target HTML 與該 HTML 直接引用的 same-host / in-scope JS files。
- 不會請求 JS 中提取出的 API endpoint；這些 endpoint 只會加入 inventory candidates。
- 不執行 JavaScript，不 evaluate JavaScript，不提交表單，不使用 cookie / token / credential。
- 不進行 exploit、fuzzing、bruteforce、DoS 或 state-changing action。

## Bounded In-Scope Crawling

v0.4 允許未來加入 bounded in-scope crawling，但禁止 unrestricted crawling 與 unlimited recursive crawling。

建議未來 workflow：

```text
workflows/safe_bounded_crawl_workflow.py
```

建議未來 tools：

```text
tools/html_link_extractor.py
tools/crawl_queue.py
```

`safe_bounded_crawl_workflow` 建議 `risk_level=medium`，必須先通過 `risk_gate` 與 explicit approval。

Bounded crawler 必須遵守：

- 只允許 in-scope domain / subdomain。
- 只允許 `GET` / `HEAD`。
- 不允許 `POST` / `PUT` / `PATCH` / `DELETE`。
- 不提交 form。
- 不使用 cookie / token / credential。
- 不 exploit。
- 不 fuzz。
- 不 brute force。
- 不做 state-changing action。
- 限制 `max_pages`。
- 限制 `max_depth`。
- 限制 `max_requests`。
- 限制 `rate_delay_seconds`。
- 只處理允許的 content-type，例如 HTML 與安全的 text metadata。
- 只追蹤 same-scope link。
- 不保存 cookie、token、secret、personal data、payment data 或完整敏感 response body。

Crawler 可以收集：

- HTML links。
- Script `src`。
- Sitemap links。
- Same-scope frontend routes。

Crawler 不會自動請求 JS 中萃取出的 API endpoint。API candidates 只應加入 inventory，等待後續 risk gate、approval 與 controlled validation。

這些後續 workflow 必須各自遵守 scope guard、risk gate、request limit、safety metadata、敏感資料保護與 approval 規則。

## 安全限制

Attack surface inventory 不得進行：

- Exploit。
- Fuzzing。
- Bruteforce。
- Credential testing。
- Credential stuffing。
- DoS 或 stress testing。
- Destructive action。
- Unrestricted exploit chaining。
- Unrestricted crawling。
- Unlimited recursive crawling。
- Real data exfiltration。

若後續 validation 需要 medium/high risk action，必須通過 `risk_gate` 與 explicit approval。若 target 不在 scope 內，必須停止。
