# Attack Surface Inventory

本文件說明 `v0.4-attack-surface-inventory` 目前已完成的 attack surface inventory 能力、安全邊界、request budget，以及 v0.4 與 v0.5 的分界。

## 目前狀態

`v0.4-attack-surface-inventory` 目前標記為 completed。

v0.4 的目的，是在授權且 in-scope 的目標上建立安全、可審計的 attack surface inventory。Inventory 只用來回答「有哪些公開入口點、來源是什麼、可能是哪類 endpoint、後續應如何排序」，不是漏洞證明，也不是自動漏洞驗證。

## 已完成內容

v0.4 已完成下列基礎能力：

* Attack surface inventory foundation。
* `tools/url_normalizer.py`。
* `tools/endpoint_inventory.py`。
* `validators/inventory_validator.py`。
* `workflows/safe_robots_securitytxt_workflow.py`。
* `workflows/safe_sitemap_parser_workflow.py`。
* `tools/js_endpoint_extractor.py`。
* `workflows/safe_js_endpoint_extraction_workflow.py`。
* `tools/html_link_extractor.py`。
* `tools/crawl_queue.py`。
* `workflows/safe_bounded_crawl_workflow.py`。
* v0.4 tools 的 risk profiles。
* v0.4 workflows 的 MCP wrappers。
* v0.4 workflow tests。

目前已暴露給 LM Studio 的 v0.4 MCP tools：

```text
tool_safe_robots_securitytxt_workflow
tool_safe_sitemap_parser_workflow
tool_safe_js_endpoint_extraction_workflow
tool_safe_bounded_crawl_workflow
```

## 安全邊界

v0.4 只建立 attack surface inventory，不確認漏洞成立。

v0.4 不做：

* Exploit。
* Fuzzing。
* Brute force。
* Credential testing。
* Form submission。
* State-changing action。
* DoS 或 stress testing。
* Destructive action。
* Real data exfiltration。
* Sensitive data storage。
* Unrestricted crawling。
* Unlimited recursive crawling。

Inventory 與 evidence 只能保存非敏感 metadata，例如 normalized URL、discovery source、status code、content type、body size、safe headers summary、endpoint type、priority、confidence。不得保存 cookie、token、secret、personal data、payment data 或完整敏感 response body。

`safe_bounded_crawl_workflow` 是 medium risk，必須經過 `risk_gate` 與 explicit approval 才能執行。

## Request Budget

v0.4 workflows 的 request budget 如下：

| Workflow | Risk level | Max requests | 說明 |
| --- | --- | ---: | --- |
| `safe_robots_securitytxt_workflow` | low | 3 | 只觀察 `/robots.txt`、`/.well-known/security.txt`、`/sitemap.xml`。 |
| `safe_sitemap_parser_workflow` | low | 1 | 只請求 `/sitemap.xml`，不請求 sitemap 內列出的 URL。 |
| `safe_js_endpoint_extraction_workflow` | medium | 31 | 1 個 target HTML request 加上最多 30 個 same-scope JS requests。 |
| `safe_bounded_crawl_workflow` | medium | 30 | 受 `max_pages`、`max_depth`、`max_requests` 與 `rate_delay_seconds` 限制。 |

## Workflow 說明

### robots/security.txt/sitemap metadata

`safe_robots_securitytxt_workflow` 只觀察固定 public metadata paths：

```text
/robots.txt
/.well-known/security.txt
/sitemap.xml
```

它不會自動掃 robots.txt 裡列出的 path，也不會把 `Disallow` 視為掃描授權。

### Sitemap parser

`safe_sitemap_parser_workflow` 只請求 in-scope target 的 `/sitemap.xml`，解析 XML 中的 URL，並把 same-scope candidates 轉成 inventory candidates。

它不會自動請求 sitemap 內列出的每個 URL，也不會做無限制遞迴 sitemap index 解析。

### JavaScript endpoint extraction

`safe_js_endpoint_extraction_workflow` 用於大型前端站點的 bounded static extraction。

它會請求 target HTML，從 HTML 中找出 directly referenced same-scope JavaScript files，並對有限數量的 JS 文字做靜態 endpoint candidate extraction。

它不執行 JavaScript、不 evaluate JavaScript、不請求 JS 中提取出的 API endpoint。JS 中提取出的 endpoint 只會成為 inventory candidate。

### Bounded in-scope crawl

`safe_bounded_crawl_workflow` 是 bounded in-scope crawler，不是 unrestricted crawler。

它只處理 same-host 或 configured in-scope links，並受下列限制約束：

* `max_pages`。
* `max_depth`。
* `max_requests`。
* `rate_delay_seconds`。
* allowed content type，例如 `text/html` 與 `application/xhtml+xml`。

它可以從 HTML 中收集：

* `<a href>`。
* `<script src>`。

`<a href>` 可加入 crawl queue；`<script src>` 只會成為 inventory candidate，不會由 crawler 下載。JavaScript endpoint extraction 由 `tool_safe_js_endpoint_extraction_workflow` 負責。

Crawler 不提交 form、不使用 cookies/tokens/credentials/session、不使用 POST/PUT/PATCH/DELETE、不做 state-changing action。

## Endpoint Inventory Schema

Inventory item 應盡量符合下列資料模型：

```json
{
  "target": "",
  "url": "",
  "normalized_url": "",
  "source": "robots | security_txt | sitemap | html_link | html_script_tag | javascript_static_analysis | manual",
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

## Conservative Classification

`inventory_validator.py` 只做保守分類與降噪，不聲稱任何漏洞成立。

常見 endpoint type：

* `api`
* `auth_page`
* `admin_candidate`
* `static_asset`
* `documentation`
* `frontend`
* `unknown`

Priority 只代表後續 triage 或 controlled validation 的排序參考，不代表漏洞嚴重度。

## v0.4 與 v0.5 分界

v0.4 only builds attack surface inventory。

v0.5 should focus on controlled validation planning。可能範圍包含：

* Controlled open redirect observation。
* Controlled exposed file observation。
* Controlled GraphQL observation。
* Authz / IDOR validation preparation。

v0.5 尚未完成。後續 v0.5 的任何 validation workflow 仍必須使用：

* Scope guard。
* Risk gate。
* Explicit approval。
* Request limits。
* Evidence rules。
* Sensitive-data minimization。

v0.5 不應繞過 v0.4 建立的 inventory、安全 metadata、risk profiles 或 approval 邊界。
