# aipocket

> 基于 FOFA 的 AI 基础设施暴露面扫描器：从公网暴露的 AI 网关 / 代理中提取并验证泄露的 `apikey` + `apiurl` 组合。

aipocket 以一份 AI 相关 CVE 清单为线索，自动生成 **FOFA** 与 **Shodan** 两套查询语句，拨取命中主机的 `header` / `banner` / `cert` / `title` 等字段，用正则 + GPT 双重提取疑似密钥与接口地址，再对其发起探测请求以判定密钥是否有效、属于哪个额度等级（tier）、网关余额多少，最后把结果落盘为 JSON。

---

## ⚠️ 合规与免责声明

本项目仅用于**已获授权的安全研究、泄露凭证排查与红蓝对抗演练**。

- 请勿对未经授权的系统进行扫描或探测。
- 请勿使用、转售或滥用任何第三方泄露的 API 密钥——未经授权使用他人凭证可能触犯法律，并会消耗他人账户的真实费用。
- 推荐用途：检测**自己组织**的密钥是否已泄露到公网，以便及时吊销。

使用者需自行承担因使用本工具产生的一切后果。

---

## 工作原理

```
步骤                          命令
─────────────────────────────────────────────────────────
1. 同步 CVE 清单              aipocket cve-sync
   Tavily 搜 AI 漏洞 → 补充 sources/cve_2026_ai.json
   ↓
2. 生成查询语句           aipocket scan --fast
   queries.build_queries() / shodan_queries.build_shodan_queries()
   同一份 CVE → FOFA 语句 + Shodan 语句（两套语法）
   ↓
3. 双源拨取命中主机
   fofa_client.FofaClient     FOFA：多 key 轮询、分页、自动剔除失效 key
   shodan_client.ShodanClient Shodan：多 key 轮询、分页、`data`(banner)+`http.html`(body)
   两个来源的 hits 合并，每条打上 `_source` 标记
   ↓
4. 双重提取凭证
   extractor (正则 + 误报黑名单)  →  analyzer (GPT 批量补充)
   ↓
5. 探测验证
   validator                校验返回体是真实 chat completion JSON
   ↓
6. GPT 二次校验
   analyzer.recheck          排除 SPA/WAF/欢迎页误报
   ↓
7. 余额查询
   balance                   LiteLLM / One-API / New-API / OpenAI billing
   ↓
8. 写盘
   writer.write_result       results/scan_*.json + valid_*.json
   结果里会记录来源：`sources` / `hits_by_source` / 每条凭证的 `backend`
```

> 一文 `scan` 会同时走 FOFA 与 Shodan 两个独立后端（各自独立的客户端与查询语法），
> 结果合并后走同一条提取→验证→余额流水线。某个来源未配置 key 时会自动跳过。

`scheduler.Scheduler` 在以上流程之上提供周期性执行能力。

---

## 环境要求

- Python ≥ 3.11
- 推荐使用 [uv](https://github.com/astral-sh/uv) 管理依赖

---

## 安装

```bash
uv sync                      # 安装运行依赖
uv sync --extra dev          # 连同开发依赖（ruff / pytest 等）一起安装
```

---

## 配置

```bash
cp .env.example .env
```

`.env` 字段说明：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `FOFA_KEYS` | （空） | 逗号分隔的 FOFA key，支持多 key 轮询与容错 |
| `FOFA_BASE_URL` | `https://fofoapi.com` | FOFA 代理地址 |
| `FOFA_PAGE_SIZE` | `100` | 每页结果数（上限 100） |
| `FOFA_MAX_PAGES` | `10` | 每条查询最多翻页数 |
| `FOFA_TIMEOUT` | `30` | FOFA 请求超时（秒） |
| `VALIDATE_CONCURRENCY` | `20` | 密钥验证并发数 |
| `VALIDATE_TIMEOUT` | `15` | 单次验证探测超时（秒） |
| `SCHEDULER_ENABLED` | `false` | 是否启用周期调度 |
| `SCHEDULER_INTERVAL` | `3600` | 调度间隔（秒） |
| `TAVILY_BASE_URL` | （空） | Tavily 代理地址（CVE 同步用） |
| `TAVILY_KEY` | （空） | Tavily 代理 key |
| `GPT_BASE_URL` | （空） | GPT 三方 API 地址（留空则跳过 GPT 增强） |
| `GPT_KEY` | （空） | GPT 三方 API key |
| `GPT_MODEL` | `gpt-4o-mini` | GPT 模型名 |
| `GPT_FAST` | `false` | 快速模式：10 并发 + 30 hits/批 + `reasoning_effort=medium` |
| `RESULTS_DIR` | `results` | JSON 结果输出目录 |

> ⚠️ `.env` 含真实密钥，已被 `.gitignore` 忽略，请勿提交。

---

## 使用

```bash
# 1. 同步 CVE 清单（Tavily 实时搜索 AI 相关漏洞，补充到 sources/cve_2026_ai.json）
uv run aipocket cve-sync

# 2. 扫描（FOFA + Shodan 双源拨取 → 提取密钥 → 探测验证 → GPT 二次校验 → 余额查询 → 写 JSON）
uv run aipocket scan --fast

# 3. 查看结果（有效凭证 + 网关余额）
uv run aipocket balance
```

其他命令：

```bash
uv run aipocket scan -n 5 -v       # 只跑前 5 条查询（调试）
uv run aipocket queries             # Dry-run：列出将执行的 FOFA + Shodan 查询
uv run aipocket config              # 查看当前配置（key 脱敏）
uv run aipocket shodan-info         # 查看 Shodan 套餐与剩余查询积分
uv run aipocket watch               # 周期执行（需 SCHEDULER_ENABLED=true）
```

---

## Fast 模式

GPT 增强分析默认使用 **5 并发 + 15 hits/批**。开启 `--fast` 或 `GPT_FAST=true` 后切换为 **10 并发 + 30 hits/批 + `reasoning_effort=medium`**：

| | 普通模式 | Fast 模式 |
|---|---|---|
| GPT extract 并发 | 5 | 10 |
| GPT extract 批大小 | 15 hits/请求 | 30 hits/请求 |
| GPT reasoning_effort | （默认） | medium |
| 500 hits 预估耗时 | ~60s | ~15s |

---

## 输出说明

每次 `scan` / 调度运行后，`results/` 目录生成：

| 文件 | 内容 |
|------|------|
| `scan_<时间戳>.json` | 完整结果：查询、命中、全部凭证及验证详情 |
| `valid_<时间戳>.json` | 仅保留**验证有效**的凭证（含 tier / gateway / balance） |
| `latest_scan.json` | 最近一次完整结果（符号链接） |
| `latest_valid.json` | 最近一次有效凭证结果 |

`ValidationResult` 字段：

| 字段 | 说明 |
|------|------|
| `credential.backend` | **发现来源**：`fofa` / `shodan` / `fofa,shodan`（同一密钥被两个来源都发现时合并） |
| `valid` | 是否真正有效（通过 chat completion JSON 校验 + GPT 二次确认） |
| `status_code` | 探测 HTTP 状态码 |
| `tier` | 额度等级（tier5 / tier4 / tier3 / limit:N） |
| `gateway` | 网关类型（litellm / oneapi / newapi / openai） |
| `balance` | 余额（USD） |
| `model_available` | 探测成功的模型名 |
| `rate_limit_headers` | 速率限制相关响应头 |
| `response_snippet` | 响应体片段 |

时间戳为 UTC，格式 `YYYYMMDDTHHMMSSZ`。

结果文件还包含两个来源字段：`sources`（本次运行启用的来源列表，如 `["fofa","shodan"]`）与 `hits_by_source`（各来源命中数）。

---

## 开发

```bash
uv run pytest -q                    # 运行测试（respx 拦截 HTTP，不发真实请求）
uv run ruff check src/ tests/       # 静态检查
uv run ruff check --fix src/ tests/ # 自动修复
```
