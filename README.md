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
    → GPT 二次校验 → 余额查询 → 写盘 JSON
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

# 扫描
uv run aipocket scan --fast

# 查看结果
uv run aipocket balance
```

### Docker 部署

镜像采用多阶段构建：先用 `node:20-slim` 通过 pnpm 构建 React 前端（`frontend/dist`），再拷贝到 Python 镜像并经 `WEB_STATIC_DIR` 由后端静态托管。默认 `serve` 模式**只启动 Web 服务、不会自动扫描**——扫描一律从 Web UI 触发（或用一次性 CLI）。

```bash
# 构建并启动（默认 serve 模式，Web API + 前端在 / 根路径，监听 8000 端口，不会自动扫描）
docker compose up -d

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

# 查看结果
ls /data/aipocket/results/
```

容器数据持久化到宿主机 `/data/aipocket/`，目录结构：

```
/data/aipocket/
├── .env              # 配置文件（首次自动生成）
├── results/          # 扫描结果
│   └── run_YYYY_MM_DD_HH-MM-SS/
│       ├── run.log
│       ├── scan_*.json
│       ├── valid_*.json
│       └── raw_hits_*.json
└── sources/          # CVE 数据（预留）
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
| `RESULTS_DIR` | `results` | 结果输出目录 |

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

## 输出格式

每次扫描生成 `results/run_YYYY_MM_DD_HH-MM-SS/` 目录：

| 文件 | 内容 |
|------|------|
| `scan_*.json` | 完整结果：查询、命中、全部凭证及验证详情 |
| `valid_*.json` | 仅有效凭证（含 tier / gateway / balance） |
| `raw_hits_*.json` | FOFA/Shodan 原始命中数据 |
| `run.log` | 本次扫描日志 |

`ValidationResult` 关键字段：`valid`、`tier`（tier3-5）、`gateway`（litellm/oneapi/newapi）、`balance`（USD）、`credential.backend`（fofa/shodan/both）。

---

## 开发

```bash
uv sync --extra dev                 # 安装开发依赖
uv run pytest -q                    # 运行测试（respx mock，不发真实请求）
uv run ruff check src/ tests/       # 静态检查
```

项目文档见 `docs/` 目录。
