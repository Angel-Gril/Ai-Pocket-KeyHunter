# aipocket

> 基于 FOFA 的 AI 基础设施暴露面扫描器：从公网暴露的 AI 网关 / 代理中提取并验证泄露的 `apikey` + `apiurl` 组合。

aipocket 以一份 AI 相关 CVE 清单为线索，自动生成 FOFA 查询语句，抓取命中主机的 `header` / `banner` / `cert` / `title` 等字段，用正则提取疑似密钥与接口地址，再对其发起探测请求以判定密钥是否有效、属于哪个额度等级（tier），最后把结果落盘为 JSON。

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
CVE 清单 (sources/cve_2026_ai.json)
        │  queries.build_queries()      按漏洞类型/CVSS 排序，套用产品指纹模板
        ▼
   FOFA 查询语句
        │  fofa_client.FofaClient       多 key 轮询、分页、自动剔除失效 key
        ▼
   命中主机原始字段
        │  extractor.extract_credentials  正则提取 apikey / 推断 apiurl，去重
        ▼
   候选凭证 (Credential)
        │  validator.validate_all       并发探测 /v1/chat/completions，判定有效性 + tier
        ▼
   验证结果 (ValidationResult)
        │  writer.write_result          写入 scan_*.json / valid_*.json / latest_*
        ▼
      results/ 目录
```

`scheduler.Scheduler` 在以上流程之上提供周期性执行能力。

---

## 环境要求

- Python ≥ 3.11
- 推荐使用 [uv](https://github.com/astral-sh/uv) 管理依赖

---

## 安装

```bash
# 使用 uv（推荐）
uv sync                      # 安装运行依赖
uv sync --extra dev          # 连同开发依赖（ruff / pytest 等）一起安装

# 或使用 pip
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

---

## 配置

复制示例配置并填入你自己的 FOFA key：

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
| `SCHEDULER_INTERVAL` | `3600` | 调度间隔（秒），3600 = 1 小时 |
| `RESULTS_DIR` | `results` | JSON 结果输出目录 |

> ⚠️ `.env` 含真实密钥，已被 `.gitignore` 忽略，请勿提交。仓库内的 `.env.example` 只应包含占位符。

---

## 使用

安装后可用 `aipocket` 命令；未安装时也可用 `python -m aipocket.cli`。

```bash
# 单次扫描，并把结果写入 results/ 目录
aipocket scan

# 只跑前 5 条查询（调试用），并打开详细日志
aipocket scan -n 5 -v

# Dry-run：仅列出将要执行的 FOFA 查询，不实际请求
aipocket queries

# 查看当前生效配置（key 自动脱敏）
aipocket config

# 周期执行（前台运行调度器，需 SCHEDULER_ENABLED=true）
aipocket watch
```

`scan` 命令选项：

| 选项 | 简写 | 说明 |
|------|------|------|
| `--max-queries N` | `-n` | 限制执行的 FOFA 查询条数，`0` 表示全部 |
| `--verbose` | `-v` | 输出 DEBUG 级日志 |

---

## 输出说明

每次 `scan` / 调度运行后，`results/` 目录会生成：

| 文件 | 内容 |
|------|------|
| `scan_<时间戳>.json` | 完整结果：查询、命中、全部凭证及验证详情 |
| `valid_<时间戳>.json` | 仅保留**验证有效**的凭证 |
| `latest_scan.json` | 指向最近一次完整结果（符号链接，失败时退化为副本） |
| `latest_valid.json` | 指向最近一次有效凭证结果 |

时间戳为 UTC，格式 `YYYYMMDDTHHMMSSZ`。

---

## 项目结构

```
gptSteal/
├── pyproject.toml              # 项目与依赖定义（包名 aipocket）
├── .env.example                # 配置示例（占位符，勿放真实 key）
├── sources/
│   └── cve_2026_ai.json        # AI 相关 CVE 清单，查询线索来源
├── src/aipocket/
│   ├── cli.py                  # Typer 命令行入口（scan/watch/queries/config）
│   ├── config.py               # pydantic-settings 读取 .env
│   ├── queries.py              # 由 CVE 清单生成 FOFA 查询
│   ├── fofa_client.py          # FOFA 搜索客户端（多 key 轮询 + 分页）
│   ├── extractor.py            # 从命中字段中正则提取 apikey / apiurl
│   ├── validator.py            # 并发探测密钥有效性与 tier
│   ├── writer.py               # 结果写盘（JSON + latest 链接）
│   ├── scheduler.py            # 周期调度器
│   └── models.py               # Credential / ValidationResult 等数据模型
├── tests/                      # pytest 测试套件
└── results/                    # 输出目录（已被 gitignore 忽略）
```

---

## 开发

```bash
# 运行测试
pytest -q

# 静态检查
ruff check src/ tests/

# 自动修复可修复项
ruff check --fix src/ tests/
```

测试使用 `respx` 拦截 HTTP，不会发起真实网络请求，可放心在本地运行。
