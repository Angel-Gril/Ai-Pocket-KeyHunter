# aipocket

> 基于 FOFA + Shodan + GitHub Artifact Hunter 的 AI 基础设施暴露面扫描器：发现暴露目标与泄露凭证，完成归因、验证、余额查询和持久化。

---

## 免责声明

本项目仅用于**已获授权的安全研究与泄露凭证排查**。请勿对未授权系统扫描、勿滥用泄露密钥。使用者自行承担一切后果。

---

## 项目结构

```
aipocket/
├── backend/                     # Python 后端 (FastAPI + Typer CLI)
│   ├── src/aipocket/
│   │   ├── core/                # 基础设施：配置、数据库、模型、Key 模式
│   │   ├── clients/             # 外部 API 客户端 (FOFA, Shodan, GitHub, Tavily)
│   │   ├── discovery/           # 数据源注册、GitHub Hunter、Provider Packs
│   │   ├── services/            # 业务逻辑：扫描、验证、去重、写入等
│   │   ├── prober/              # 网关指纹探测器 (Dify, LiteLLM, NewAPI 等)
│   │   ├── api/                 # FastAPI 路由、鉴权、Schema、扫描管理器
│   │   ├── cli.py               # Typer CLI 入口
│   │   └── scheduler.py         # 周期调度
│   ├── tests/                   # 按模块分层的测试
│   │   ├── core/                # 配置、模型测试
│   │   ├── clients/             # FOFA、Shodan 客户端测试
│   │   ├── services/            # 扫描、验证、写入等测试
│   │   ├── prober/              # 探测器测试
│   │   └── api/                 # Web API、CLI 测试
│   ├── scripts/
│   │   ├── oneoff/              # 一次性迁移 / 调试脚本
│   │   └── reports/             # HTML 报告生成
│   ├── sources/                 # CVE 数据文件
│   ├── pyproject.toml
│   └── Dockerfile               # 仅后端
├── frontend/                    # React + Vite + TailwindCSS
│   ├── src/
│   │   ├── pages/               # 路由页面 (登录、扫描、历史等)
│   │   ├── components/          # UI 组件 (shadcn + 业务组件)
│   │   ├── providers/           # Auth Context
│   │   └── lib/                 # API 客户端、工具函数
│   ├── Dockerfile               # Node 构建 + Nginx 托管
│   ├── nginx.conf               # 静态文件 + API 反向代理
│   └── package.json
├── docker-compose.yml           # 生产编排：backend + frontend + PG + Redis
├── docker-compose.override.yml  # 开发覆盖：热重载
├── .env.example                 # 所有环境变量
└── README.md
```

---

## 当前执行机制

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ 入口                                                                        │
│ CLI: aipocket scan              Web: POST /api/scan/start                   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ run_scan                                                                    │
│ 选择 source / GitHub pack / full|incremental 策略 / 查询预算                │
│ 获取单实例 ScanLease                                                        │
│ PostgreSQL 启用时：先创建 runs(state=running)，再启用 RequestLedger flush   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌────────────────────────────── SourceRegistry ───────────────────────────────┐
│                                                                             │
│  FOFA ── Query Planner ── API ──┐                                           │
│                                  ├── Host Hits ── canonicalize_hits          │
│ Shodan ─ Query Planner ── API ──┘                    │                      │
│                                                      ├── 正则提取凭证       │
│                                                      ├── 证据门控 Prober    │
│                                                      └── 可选 GPT 提取      │
│                                                                             │
│ GitHub ── Provider Pack ──┬── Commit Message Search                         │
│                           ├── Code Snapshot（每次从 Page 1 + ETag 开始）    │
│                           └── Seeded File History                           │
│                                      │                                      │
│                                      ▼                                      │
│          Public-only 检查 ── Checkpoint + Work Queue ── Artifact 提取       │
│                                      │                                      │
│                                      └── CredentialSourceObservation        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌──────────────────────────── 共享凭证处理流水线 ─────────────────────────────┐
│ ObservationRegistry（来源、query、pack、文件/SHA/行号归因）                 │
│      │                                                                      │
│      ▼                                                                      │
│ 格式预过滤 ── Redis 跨 run 去重/缓存 ── Provider Registry 官方端点路由      │
│      │                                                                      │
│      ▼                                                                      │
│ 只读凭证验证 ── Forged-key No-Auth 检测 ── 可选 GPT Recheck                │
│      │                                                                      │
│      ▼                                                                      │
│ Finalizer（有效 / 拒绝 / 瞬态 / 限流待确认）── 余额与账户信息补全           │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                  ┌────────────────────┴────────────────────┐
                  ▼                                         ▼
┌──────────────────────────────────────┐   ┌──────────────────────────────────┐
│ PostgreSQL 最终事务                  │   │ Run 目录 JSONL                   │
│ runs(state=finished)                 │   │ scan / valid / suspicious        │
│ results / query_metrics              │   │ probe findings / debug artifacts │
│ validation & extraction aggregates   │   └──────────────────────────────────┘
└──────────────────┬───────────────────┘
                   │
                   ▼
          FastAPI 查询接口 ── React Web UI

所有物理 HTTP 尝试
        │
        └── RequestLedger（source + query_id + pack_id + stage）
                 │
                 ├── 覆盖完整且 flush 成功：生成 Metrics v3 HTTP 成本
                 └── 覆盖不完整或持久化失败：降级为 Metrics v2
```

GitHub-only 扫描要求 `GITHUB_TOKENS` 和 `DATABASE_URL`，缺少任一项都会 fail closed；
GitHub v1 只处理响应中明确标记为公开的仓库。

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
#    文档: http://localhost:8000/docs

# 可选: 定时扫描守护
docker compose --profile watch up -d backend-watch

# 可选: 历史数据回填到 PostgreSQL
docker compose --profile import run --rm backend-import
```

### 本地开发

```bash
# 后端
cd backend
uv sync --extra dev          # 安装依赖
cp ../.env.example ../.env   # 配置（编辑填入密钥）
uv run pytest -q             # 运行测试
uv run aipocket serve --reload   # 启动 API (端口 8000)

# 前端（另一个终端）
cd frontend
pnpm install                 # 安装依赖
pnpm dev                     # 启动开发服务器 (端口 5173, 代理 /api → :8000)
```

> 本地 `uv run` 直连 PG 时 `DATABASE_URL` 的 host 用 `localhost`；容器内运行由 compose 自动注入指向 `postgres` 服务。

---

## 命令一览

```bash
aipocket scan [--fast] [-n N] [-v]     # 扫描（-n 限制查询数）
aipocket scan --realtest -v            # 小批量真测（精简 CVE + 默认 -n 3）
aipocket watch                         # 周期执行（需 SCHEDULER_ENABLED=true）
aipocket serve [--host H] [--port P]   # 启动 Web API
aipocket balance                       # 查询最近扫描结果的余额
aipocket cve-sync                      # 同步 CVE 清单
aipocket queries                       # 列出将执行的查询（dry-run）
aipocket config                        # 查看当前配置（key 脱敏）
aipocket shodan-info                   # Shodan 套餐与剩余积分
```

---

## Web API

`aipocket serve` 提供 HTTP 服务层，供 React 前端调用。

- **鉴权**：单一全局密码。`POST /api/auth/login` 换取 JWT，其余接口以 `Authorization: Bearer <token>` 携带。
- **主要端点**：`/api/runs`、`/api/high-value`、`/api/key/{models,balance,chat,reveal}`、`/api/export`、`/api/scan/{start,stop,status,logs/stream}`、`/api/cve[/sync]`、`/api/settings`、`/api/system/restart`。
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
cd backend
uv sync --extra dev                 # 安装开发依赖
uv run pytest -q                    # 运行测试
uv run ruff check src/ tests/       # 静态检查
```

项目文档见 `docs/` 目录。

---

## License

AGPL-3.0-or-later
