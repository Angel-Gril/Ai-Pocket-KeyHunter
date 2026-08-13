<div align="center">
  <img src="docs/images/lion-avatar-round.png" alt="AIPocket lion" width="220">
  <br>
  <h3><strong>Tonight We Hunt!</strong></h3>
  <p>
    <img src="https://img.shields.io/badge/platform-Docker%20%7C%20Linux-6f42c1" alt="Platform: Docker and Linux">
    <img src="https://img.shields.io/badge/Rust-1.88-000000?logo=rust&amp;logoColor=white" alt="Rust 1.88">
    <img src="https://img.shields.io/badge/Axum-0.8-000000" alt="Axum 0.8">
    <img src="https://img.shields.io/badge/React-19-20232a?logo=react&amp;logoColor=61DAFB" alt="React 19">
    <img src="https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&amp;logoColor=white" alt="PostgreSQL 16">
    <img src="https://img.shields.io/badge/Redis-7-DC382D?logo=redis&amp;logoColor=white" alt="Redis 7">
    <img src="https://img.shields.io/badge/coverage-90.1%25-brightgreen" alt="Line coverage: 90.1%">
    <img src="https://img.shields.io/badge/license-AGPL--3.0--or--later-5c940d" alt="License: AGPL-3.0-or-later">
  </p>
  <p>
    <a href="#界面预览">界面预览</a> ·
    <a href="#快速开始">快速开始</a> ·
    <a href="#命令一览">命令一览</a> ·
    <a href="#web-api">Web API</a> ·
    <a href="#配置">配置</a> ·
    <a href="#开发">开发</a>
  </p>
</div>

<div align="center">
  <h1>aipocket</h1>
</div>



> 一起打野！基于 FOFA、Shodan 与 GitHub Artifact Hunter，自动发现 AI 基础设施暴露面与泄露凭证，并完成归因、验证、余额查询和持久化。

---

## 免责声明

本项目仅用于**已获授权的安全研究与泄露凭证排查**。请勿对未授权系统扫描、勿滥用泄露密钥。使用者自行承担一切后果。

---

## 合并说明（Ai-Pocket-KeyHunter）

本仓库在 AI Pocket 基础上完整合并了 [keyHunter](https://github.com/lifefloating/keyHunter-skill)（位于 `tools/keyhunter/`，Python CLI，功能含面板发现、指纹、弱口令测试、账户导出、制品归一化），并在 Rust 平台增加了 `ai_gateway` 发现包与 `sub2api`/`oneapi` 被动指纹探测器。

功能与边界分析见 [docs/keyhunter-integration-analysis.md](docs/keyhunter-integration-analysis.md)。

**许可证提示**：keyHunter 使用限制性许可证（keyHunter Defensive Security Source License v1.0），其第 5 条禁止再分发；本仓库含 keyHunter 代码，对外分发/托管前请自行确认授权。

---

## 界面预览

![全部密钥与余额状态](docs/images/all-keys.jpg)

[查看其余界面截图 →](docs/screenshots.md)

---

## QQ 交流群

群号：`1049528428`

<p align="center">
  <img src="docs/images/qq-group.jpg" alt="sbclaude × AI 开发交流群二维码，群号 1049528428" width="360">
</p>

---

## 项目结构

```
aipocket/
├── Cargo.toml / Cargo.lock       # Rust 2024 workspace
├── crates/
│   ├── aipocket/                 # Clap CLI + Axum serve 装配
│   ├── aipocket-core/            # Settings、领域模型、URL 规范化
│   ├── aipocket-db/              # SQLx 仓库、Redis dedup/scan lease
│   ├── aipocket-clients/         # FOFA / Shodan / GitHub / Tavily
│   ├── aipocket-discovery/       # Sources + Provider Packs
│   ├── aipocket-prober/          # Prober / 风险门控 / Validator
│   ├── aipocket-services/        # Scanner / Balance / Scheduler
│   └── aipocket-api/             # Axum API / JWT / SSE / ScanManager
├── frontend/                     # React + Vite + TailwindCSS
├── Dockerfile                    # Rust 多阶段后端镜像
├── docker-compose.yml            # backend + frontend + PG16 + Redis7
├── .env.example                  # 环境变量配置模板
└── docs/
```

---

## 当前执行机制

![扫描执行流水线](docs/images/flow.png)

GitHub-only 扫描要求 `GITHUB_TOKENS` 和 `DATABASE_URL`，缺少任一项都会 fail closed；
GitHub v1 只处理响应中明确标记为公开的仓库。

---

## Rust 相对 Python 的预期性能提升

后端已从 Python 迁至 Rust 2024 workspace（Axum + Tokio + Reqwest + SQLx）。在同等 VPS 与并发配置下，粗略预期：

| 维度 | 预期提升 | 说明 |
|------|----------|------|
| 端到端扫描吞吐 | **约 +40% ~ +80%** | 去掉 Python GIL / 解释器开销，Tokio 异步并发更稳 |
| 验证阶段（validate） | **约 +50% ~ +120%** | 高并发 HTTP 验证是主路径；连接复用与更低 per-task 内存 |
| 峰值内存 | **约 -30% ~ -50%** | spill 表 + 批处理，避免 Python 大对象与 runtime 膨胀 |
| API / SSE 延迟 | **约 -20% ~ -40%** | Axum 冷路径更短，JWT/列表接口更轻 |
| 单实例 CPU 利用率 | 更高有效利用率 | 同等核数下完成更多 validate / probe 任务 |

以上为量级估算，非严格 benchmark；实际收益取决于 FOFA/Shodan/GitHub 外部限速、网络 RTT 与 `VALIDATE_CONCURRENCY`。外部 API 配额往往成为上限时，墙钟时间提升会收敛到网络侧。

---

## 快速开始

### Docker 部署（推荐）

```bash
# 1. 配置环境
cp .env.example .env
# 编辑 .env — 设置 WEB_PASSWORD、WEB_JWT_SECRET，至少配一个 FOFA_KEYS 或 SHODAN_KEYS

# 2. 启动所有服务
docker compose up -d --build

# 3. 访问
#    前端: http://localhost        (Nginx, 端口 80)
#    API:  http://localhost:8000   (后端直连)

# 可选: 定时扫描守护
docker compose --profile watch up -d backend-watch

```

### 本地开发

```bash
# Rust 后端
cp .env.example .env   # 创建本地开发配置
cargo test --workspace
cargo run -p aipocket -- serve --host 127.0.0.1 --port 8000

# 前端（另一个终端）
cd frontend
pnpm install
pnpm dev
```

> 生产环境更新服务：执行 `docker compose build backend frontend && docker compose up -d backend frontend`。PostgreSQL、Redis 和 `/data/aipocket` 均为持久化数据；禁止执行 `down -v`、删除数据目录或 flush Redis。

---

## 命令一览

```bash
aipocket scan --source all --mode incremental
aipocket watch
aipocket serve --host 0.0.0.0 --port 8000
aipocket balance
aipocket cve-sync
aipocket queries
aipocket config
aipocket shodan-info
```

---

## Web API

`aipocket serve` 由 Axum 提供 HTTP 服务，接口字段供 React 前端及其他 API 客户端使用。

- **鉴权**：单一全局密码。`POST /api/auth/login` 换取 JWT，其余接口使用 `Authorization: Bearer <token>`。
- **主要端点**：`/api/runs`、`/api/high-value`、`/api/keys`、`/api/key/*`、`/api/export`、`/api/scan/*`、`/api/cve`、`/api/honeypot`、`/api/manual-targets`、`/api/settings`。
- **密钥展示**：列表接口返回打码 apikey；`POST /api/key/reveal` 按 run 取单条明文。
- **注意**：`/api/key/chat` 会消耗目标 key 的额度，必须显式传入 `model`。

---

## 配置

`.env` 主要字段：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `FOFA_KEYS` | — | FOFA key，逗号分隔，支持多 key 轮询 |
| `SHODAN_KEYS` | — | Shodan key，逗号分隔 |
| `WEB_PASSWORD` | — | Web UI 登录密码（必填） |
| `WEB_JWT_SECRET` | — | JWT 签名密钥（必填） |
| `DATABASE_URL` | — | PostgreSQL 连接串。留空 = 仅 JSONL |
| `VALIDATE_CONCURRENCY` | `20` | 验证并发数 |
| `GPT_BASE_URL` / `GPT_KEY` | — | GPT API（留空跳过 GPT 增强） |
| `SCHEDULER_ENABLED` | `false` | 周期调度开关 |

完整字段见 `.env.example`。

---

## 数据存储

配置 `DATABASE_URL` 后，**PostgreSQL 是持久化真源**（Redis 只做跨 run 去重缓存）。

| 表 | 内容 |
|------|------|
| `runs` | 每次扫描的元数据、计数、完整 `run.log` |
| `results` | 每条有效/可疑凭证；`record JSONB` 存完整 ValidationResult |
| `high_value_keys` | 跨 run 累积的高价值 key（按 apikey 去重） |
| `cves` | AI CVE 清单（Tavily 同步） |

备份恢复：

```bash
# 备份
docker compose exec -T postgres pg_dump -U aipocket aipocket > backup.sql
# 恢复
docker compose exec -T postgres psql -U aipocket -d aipocket < backup.sql
```

---

## 开发

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo llvm-cov --workspace --fail-under-lines 86
cd frontend && pnpm lint && pnpm test -- --run && pnpm build
```

项目文档见 `docs/` 目录。

---

## License

AGPL-3.0-or-later

---

## 🌟 Special Thanks

<p align="center">
  <a href="https://linux.do">
    <img src="docs/images/linuxdo.png" alt="LINUX DO" width="420" />
  </a>
</p>
<p align="center"><b>For all things AI, head to LINUX DO! Wishing the community ever greater success~</b></p>

---
