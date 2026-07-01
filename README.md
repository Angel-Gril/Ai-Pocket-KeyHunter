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

```bash
# 构建并启动（默认 watch 模式，定时扫描）
docker compose up -d

# 首次启动会自动将 .env.example 复制到 /data/aipocket/.env
# 编辑配置后重启
vim /data/aipocket/.env
docker compose restart

# 单次扫描
docker compose run --rm aipocket scan --fast

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
aipocket balance                       # 查询最近扫描结果的余额
aipocket cve-sync                      # 同步 CVE 清单
aipocket queries                       # 列出将执行的查询（dry-run）
aipocket config                        # 查看当前配置（key 脱敏）
aipocket shodan-info                   # Shodan 套餐与剩余积分
```

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
