# aipocket

> 基于 FOFA + Shodan 的 AI 基础设施暴露面扫描器：从公网暴露的 AI 网关/代理中提取并验证泄露的 `apikey` + `apiurl` 组合。

---

## ⚠️ 免责声明

本项目仅用于**已获授权的安全研究与泄露凭证排查**。请勿对未授权系统扫描、勿滥用泄露密钥。使用者自行承担一切后果。

---

## 工作原理

```
CVE 同步 → 生成 FOFA/Shodan 查询 → 双源拨取命中主机
    → 正则+GPT 提取凭证 → 主动探测网关 → 验证有效性
    → GPT 二次校验 → 余额查询 → 写入 PostgreSQL（未配置则回退 JSONL）
```

---

## 快速开始

### 本地运行

```bash
# 安装
uv sync

# 配置
cp .env.example .env
# 编辑 .env，填入 FOFA_KEYS / SHODAN_KEYS 等
# 可选：设置 DATABASE_URL 启用 PostgreSQL；留空则结果写 JSONL 文件

# 扫描
uv run aipocket scan --fast

# 查看结果
uv run aipocket balance
```

> 本地 `uv run` 直连 PG 时 `DATABASE_URL` 的 host 用 `localhost`（需 PG 端口映射到宿主机）；容器内运行由 compose 自动注入指向 `postgres` 服务，无需改。

### Docker 部署

镜像采用多阶段构建：先用 `node:24-slim` 通过 pnpm 构建 React 前端（`frontend/dist`），再拷贝到 Python 镜像并经 `WEB_STATIC_DIR` 由后端静态托管。默认 `serve` 模式**只启动 Web 服务、不会自动扫描**——扫描一律从 Web UI 触发（或用一次性 CLI）。

`docker compose` 一并编排四个服务：`aipocket`（Web）、`postgres`（数据真源）、`redis`（跨 run 去重缓存），以及可选的 `aipocket-watch`（定时扫描）。**PostgreSQL 是扫描结果 / 高价值 key / CVE 的持久化真源**，容器内的 `DATABASE_URL` 已由 compose 指向内置的 `postgres` 服务，无需手动配置；备份一条 `pg_dump` 即可覆盖全部数据（详见「数据存储」）。

```bash
# 构建并启动（Web + postgres + redis；默认 serve 模式，监听 8000，不会自动扫描）
docker compose up -d --build

# 首次启动会自动将 .env.example 复制到 /data/aipocket/.env
# 首次使用前务必设置 WEB_PASSWORD / WEB_JWT_SECRET（缺失则 serve 拒绝启动），
# 并按需填入 FOFA_KEYS / SHODAN_KEYS，然后重启
vim /data/aipocket/.env
docker compose restart

# 打开 Web UI（根路径）/ API 文档
open http://<vps-ip>:8000/         # Web UI
open http://<vps-ip>:8000/docs     # API 文档

# 扫描：日常从 Web UI 点击触发；如需一次性 CLI 扫描：
docker compose run --rm aipocket scan --fast

# 定时扫描守护（可选，与 Web 服务并存）
docker compose --profile watch up -d aipocket-watch

# 查看结果（数据在 PG 中；也可用 psql 直接查）
docker compose exec postgres psql -U aipocket -d aipocket -c "SELECT run_id, total_valid FROM runs ORDER BY run_id DESC;"
```

容器数据持久化到宿主机 `/data/aipocket/`（Postgres 数据在 `/data/aipocket/pg/`），目录结构：

```
/data/aipocket/
├── .env              # 配置文件（首次自动生成）
├── pg/               # PostgreSQL 数据卷（扫描结果 / 高价值 key / CVE 的真源）
├── results/          # run.log 与 raw_hits 仍落盘于此；结果记录以 PG 为准
│   └── run_YYYY_MM_DD_HH-MM-SS/
│       ├── run.log       # run 结束后同步进 PG runs.log，便于统一备份
│       └── raw_hits_*.jsonl
└── sources/          # CVE 种子 JSON（首次同步后以 PG cves 表为准）
```

#### 迁移历史数据到 PostgreSQL

若你有旧版本产生的 `results/run_*/*.jsonl`、`high_value_keys/keys.jsonl` 或 CVE JSON，用内置的一次性回填服务导入 PG（读取项目下 `./results`，可反复运行、幂等）：

```bash
# 先干跑看计数（不写库）
docker compose --profile import run --rm aipocket-import --dry-run

# 实际回填
docker compose --profile import run --rm aipocket-import
```

> 全新部署（无历史数据）可跳过这一步——首次启动 `ensure_schema()` 会自动建表。

#### 备份 / 恢复

```bash
# 备份（覆盖 runs / results / high_value_keys / cves 全部真源）
docker compose exec -T postgres pg_dump -U aipocket aipocket > aipocket_$(date +%F).sql

# 恢复
docker compose exec -T postgres psql -U aipocket -d aipocket < aipocket_2026-07-07.sql
```

---

## 命令一览

```bash
aipocket scan [--fast] [-n N] [-v]     # 扫描（-n 限制查询数）
aipocket scan --realtest -v            # 小批量真测（精简 CVE + 默认 -n 3）
aipocket watch                         # 周期执行（需 SCHEDULER_ENABLED=true）
aipocket serve [--host H] [--port P]   # 启动 Web API（FastAPI，含前端托管）
aipocket balance                       # 查询最近扫描结果的余额
aipocket cve-sync                      # 同步 CVE 清单
aipocket queries                       # 列出将执行的查询（dry-run）
aipocket config                        # 查看当前配置（key 脱敏）
aipocket shodan-info                   # Shodan 套餐与剩余积分
```

---

## Web API（FastAPI）

`aipocket serve` 在现有 CLI 之外并列提供一个 HTTP 服务层，复用同一批扫描/验证/余额业务模块，供 Vite + React 前端调用。

```bash
# 本地启动（先在 .env 设置 WEB_PASSWORD 与 WEB_JWT_SECRET）
uv run aipocket serve --port 8000 --reload
# 交互式 API 文档
open http://localhost:8000/docs
```

- **鉴权**：单一全局密码。`POST /api/auth/login` 用 `WEB_PASSWORD` 换取 JWT，其余接口以 `Authorization: Bearer <token>` 携带。
- **主要端点**：`/api/runs`（按天分组的扫描归档）、`/api/runs/{id}/valid|suspicious|log`、`/api/high-value`、`/api/key/{models,balance,chat,reveal}`、`/api/export`、`/api/scan/{start,stop,status,logs,logs/stream}`、`/api/cve[/sync]`、`/api/settings[/check/fofa|/check/shodan]`、`/api/system/restart`。
- **密钥展示**：列表接口返回**打码** apikey；`POST /api/key/reveal` 按 run 从磁盘取单条明文；`/api/export` 导出明文（后端不落盘保存）。
- **单键"测对话"（`/api/key/chat`）会消耗目标 key 的额度**，必须显式传入 `model`。

### 生产部署（nginx 反向代理 + HTTPS）

VPS 公网暴露务必走 HTTPS，密码只经加密通道传输。实时扫描日志用 SSE，需为该路径关闭 nginx 缓冲：

```nginx
location /api/scan/logs/stream {
    proxy_pass http://127.0.0.1:8000;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_buffering off;      # SSE 必须；否则日志会被缓冲、看起来"卡住"
    proxy_read_timeout 3600s;
}

location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
}
```

> `WEB_STATIC_DIR` 指向前端构建产物（`dist/`）时，后端会在 `/` 直接托管 SPA；否则仅提供 API，由反向代理托管前端。

---

## 配置

`.env` 主要字段：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `FOFA_KEYS` | — | FOFA key，逗号分隔，支持多 key 轮询 |
| `FOFA_BASE_URL` | `https://fofoapi.com` | FOFA 代理地址 |
| `SHODAN_KEYS` | — | Shodan key，逗号分隔 |
| `VALIDATE_CONCURRENCY` | `20` | 验证并发数 |
| `GPT_BASE_URL` / `GPT_KEY` | — | GPT API（留空跳过 GPT 增强） |
| `GPT_MODEL` | `gpt-4o-mini` | GPT 模型名 |
| `GPT_FAST` | `false` | 快速模式：10 并发 + 30 hits/批 |
| `SCHEDULER_ENABLED` | `false` | 周期调度开关 |
| `SCHEDULER_INTERVAL` | `3600` | 调度间隔（秒） |
| `RESULTS_DIR` | `results` | `run.log` / `raw_hits` 落盘目录 |
| `DATABASE_URL` | — | PostgreSQL 连接串。留空 = 仅用 JSONL 文件（旧行为）；设置后 PG 成为真源。compose 已自动注入 |
| `PG_POOL_MIN` / `PG_POOL_MAX` | `2` / `10` | 连接池大小 |
| `PG_DUAL_WRITE` | `false` | 默认 PG 为唯一真源。迁移已有部署时临时置 `true` 同时写 PG 与 JSONL（便于回填 / 校验 / 回退），校验无误后改回 `false` |

完整字段见 `.env.example`。

---

## Realtest 模式

小批量端到端真实测试，最小化额度消耗：

```bash
uv run aipocket scan --realtest -v          # 默认 -n 3
uv run aipocket scan --realtest -n 5 -v     # 多跑几条
```

- 使用精简 CVE 清单 `sources/cve_realtest.json`（由 `scripts/carve_realtest.py` 生成）
- 跳过通用凭证泄露查询，优先产品指纹查询（让 prober 能匹配网关型 hits）
- 可用 `AIPOCKET_CVE_PATH` 环境变量指向自定义 CVE 文件

---

## 数据存储

配置 `DATABASE_URL` 后，**PostgreSQL 是持久化真源**（Redis 只做跨 run 去重缓存）。四张表：

| 表 | 内容 |
|------|------|
| `runs` | 每次扫描一行：起止时间、状态、来源、命中数、各项计数、`run.log` 全文 |
| `results` | 每条有效 / 可疑凭证一行；`(run_id, kind, seq)` 唯一，`record JSONB` 存完整 `ValidationResult` |
| `high_value_keys` | 跨 run 累积的高价值 key，按 `apikey` 去重（UPSERT） |
| `cves` | AI CVE 清单（Tavily 同步，按 `id` UPSERT） |

`ValidationResult` 关键字段：`valid`、`tier`（tier3-5）、`gateway`（litellm/oneapi/newapi）、`balance`（USD）、`credential.backend`（fofa/shodan/both）；完整结构保存在 `record` 列，API 原样透传（读时对 apikey 打码）。

**仍落盘于 `results/run_*/` 的文件**：`run.log`（扫描中实时写，供 SSE；run 结束同步进 PG）与 `raw_hits_*.jsonl`（原始命中，体量大、仅调试用，不入库）。

> 未配置 `DATABASE_URL` 时自动退回旧的纯 JSONL 模式（`scan_*.jsonl` / `valid_*.jsonl` / `suspicious_*.jsonl`），行为与迁移前完全一致。

---

## 开发

```bash
uv sync --extra dev                 # 安装开发依赖
uv run pytest -q                    # 运行测试（respx mock，不发真实请求）
uv run ruff check src/ tests/       # 静态检查
```

项目文档见 `docs/` 目录。
