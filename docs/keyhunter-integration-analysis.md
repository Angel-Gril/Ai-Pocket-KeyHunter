# Ai-Pocket-KeyHunter: 功能与边界分析

本仓库是 **AI Pocket**（Rust 平台，AGPL-3.0-or-later）与
**keyHunter**（Python CLI，keyHunter Defensive Security Source License v1.0）
的完整合并。本文档只做客观分析，不代替使用者做安全/合规决策。

## 1. 组件总览

| 组件 | 位置 | 技术栈 | 职责 |
|---|---|---|---|
| AI Pocket 平台 | 仓库根（crates/、frontend/） | Rust + React + PostgreSQL + Redis | 资产发现、凭据验证、余额查询、持久化、Web UI |
| keyHunter CLI | `tools/keyhunter/` | Python + httpx + Typer | 面板发现、指纹、弱口令测试、账户导出、制品归一化 |
| 集成点 | `crates/aipocket-discovery/src/packs.rs`、`crates/aipocket-prober/src/products.rs` | Rust | 面板发现查询（ai_gateway pack）、被动指纹探测（sub2api/oneapi prober） |

## 2. AI Pocket 功能与边界

| 功能 | 输入 | 输出 | 网络行为 | 数据存储 | 风险面 |
|---|---|---|---|---|---|
| FOFA 发现 | FOFA_KEYS、查询 | host 命中 | 请求 fofa.info 搜索 API | PostgreSQL results / JSONL | 依赖第三方 API 配额 |
| Shodan 发现 | SHODAN_KEYS | host 命中 | 请求 Shodan API | 同上 | 同上 |
| GitHub 制品发现 | GITHUB_TOKENS + DATABASE_URL（缺失即 fail closed） | 制品命中 | GitHub 搜索 API | PostgreSQL | 仅公开仓库 |
| 被动探测（L0） | target 列表 | ProbeFinding | 对目标发 GET | PostgreSQL | 默认执行；仅读取公开端点 |
| 主动探测（L1–L3） | max_risk / intrusive_checks 显式开启 | 漏洞验证 | POST/注入/命令执行 | PostgreSQL | 默认关闭；`ProbeContext::allows()` fail-closed |
| 凭据验证 | 命中凭据 | 验证状态 | 对目标 /v1/models 等发请求 | PostgreSQL | 消耗第三方凭据额度 |
| 余额查询 | 命中凭据 | 余额/套餐 | 调用各厂商余额 API | PostgreSQL | 同上 |
| 高价值归因 | 验证结果 | high_value 记录 | 无 | PostgreSQL | 存储明文 apikey（接口打码） |
| Web API | JWT | 列表/导出 | 无 | PostgreSQL | 单全局密码；JWT 存 localStorage |
| 导出 | 选择 run/keys | CSV/JSON/Sub2API 格式 | 无 | 文件下载 | 明文密钥导出 |

## 3. keyHunter 功能与边界

| 功能 | 输入 | 输出 | 网络行为 | 数据存储 | 风险面 |
|---|---|---|---|---|---|
| discover | FOFA_KEY + 查询 | hits.json | FOFA /api/v1/search/all | 文件（--out） | 无（仅搜索引擎 API） |
| fingerprint | hits.json | alive.json | 对目标 GET（verify=False，TLS 不校验） | 文件 | 主动访问第三方主机 |
| spray | alive.json | sessions.json | 对目标 POST 登录（弱口令组合 ≈489 条 + 产品内置） | 文件 | 撞库；高并发（默认 8） |
| export | sessions.json | exports/ | 登录后接口 + IDOR `/api/token/{id}`（1..30） | 文件（明文） | 越权读取账户/令牌 |
| normalize | exports/ | artifacts/ | 无 | 文件 | 明文 API Key 落盘 |
| validate | artifacts/ | valid.json | 无（本地 JWT 解析） | 文件 | 无 |

## 4. 集成点（已实现）

1. **`ai_gateway` pack**（packs.rs）：Sub2API / New-API / One-API 面板的 FOFA/Shodan 被动发现查询（查询串来自 keyHunter 指纹）。GitHub terms 为空。
2. **`Sub2ApiProber` / `OneApiProber`**（products.rs）：纯 GET 被动探测 `/api/status`、`/v1/models`、`/api/v1/auth/login`（登录路由只探测存在性，不提交凭据）。受 `ProbeContext::allows()` fail-closed 门控：`max_risk=L0`、`intrusive_checks=false` 时仅执行被动探测。
3. **keyHunter CLI 完整保留**于 `tools/keyhunter/`：spray/export/IDOR/normalize/validate 全部可用，作为独立 CLI 由使用者显式调用（非 Web API 自动触发）。

## 5. 风险与边界（客观描述）

- **撞库**：`keyhunter spray` 默认跑完整凭据计划（约 489 条弱密码 × 内置账号）；无代码级授权范围限制、无速率限制、无二次确认。
- **TLS**：keyHunter fingerprint/spray/export 使用 `verify=False`，不验证服务器证书。
- **IDOR**：`keyhunter export` 对 New-API/One-API 枚举 `/api/token/{id}` 1..30。
- **明文存储**：keyHunter 产物（access_token、API Key）以普通 JSON 明文写盘，权限为默认 umask。
- **并发**：keyHunter 默认 8 目标并发；AI Pocket 验证并发默认 20（VALIDATE_CONCURRENCY）。
- **网络暴露**：AI Pocket docker-compose 默认将后端 8000 / 前端 3080 绑定 0.0.0.0。
- **第三方凭据**：AI Pocket 的 key/chat 端点会消耗目标 key 的额度。
- **法律/许可**：keyHunter LICENSE §4 禁止未授权使用、§5 禁止再分发（合并仓库推送到 GitHub 属于再分发，须由使用者确认）；AI Pocket 为 AGPL-3.0-or-later（网络服务修改版需提供源码）。

## 6. 使用建议（供参考，最终决定权在使用者）

- 完整管道（含 spray/export）仅建议在自有目标或书面授权范围内执行。
- 部署 AI Pocket 时建议：绑定内网/127.0.0.1、反向代理 + TLS、轮换默认口令（WEB_PASSWORD/WEB_JWT_SECRET/PostgreSQL/Redis）、数据库加密备份。
- keyHunter 的 `verify=False` 建议改为可配置 `verify=True`（代码位于 `tools/keyhunter/keyhunter/{spray,fingerprint,export}.py`）。
