# keyHunter

面向 AI 网关与配额面板安全研究的学术研究工具包（Sub2API / New-API / One-API）。仅限授权、防御性使用。

```text
FOFA 发现 → 指纹识别 → 凭据卫生测试 → 账户导出 → 制品归一化
```

本仓库完全自包含，不依赖任何其他私有狩猎/扫描仓库。

## 在 AI 工具中使用（Skill）

本仓库遵循 [agentskills.io](https://agentskills.io) 开放标准：带 YAML frontmatter 的 `SKILL.md` 即为一个技能。仓库根目录的 [SKILL.md](SKILL.md) 是完整操作手册，Claude Code、Codex 等支持该标准的工具可以直接加载。

### Claude Code

1. 在仓库根目录运行 `claude`，然后输入 `/keyhunter` 直接执行操作手册；或直接描述任务（如"用 keyhunter 对这批目标跑一遍 sub2api 全流程"），Claude 会依据技能 description 自动加载。
2. 若技能未生效，手动安装（项目级或个人级任选）：

```bash
# 项目级（仅本仓库）
mkdir -p .claude/skills/keyhunter
ln -sf ../../../SKILL.md .claude/skills/keyhunter/SKILL.md

# 个人级（所有项目可用）
mkdir -p ~/.claude/skills/keyhunter
ln -sf /path/to/keyHunter/SKILL.md ~/.claude/skills/keyhunter/SKILL.md
# 或直接复制：
# cp SKILL.md ~/.claude/skills/keyhunter/SKILL.md
```

### Codex CLI

1. 开启技能功能（一次性）：`codex --enable skills`（新版默认开启）。
2. 手动安装（项目级或个人级任选）：

```bash
# 项目级
mkdir -p .codex/skills/keyhunter
ln -sf ../../../SKILL.md .codex/skills/keyhunter/SKILL.md

# 个人级
mkdir -p ~/.codex/skills/keyhunter
ln -sf /path/to/keyHunter/SKILL.md ~/.codex/skills/keyhunter/SKILL.md
```

> 提示：`.claude/` 与 `.codex/` 目录已被 `.gitignore` 忽略，不会提交到仓库，可放心安装。

### 其他 agent（Hermes / OpenCode 等）

凡支持 agentskills.io 标准的工具，把 `SKILL.md` 放进其技能目录即可，常见位置：

- 社区约定通用目录：`.agents/skills/<name>/SKILL.md`
- OpenCode：在配置中设置 `skill.paths` 指向本仓库的 skill 目录

> 注意：软链接依赖 git 的 symlink 支持（macOS/Linux 默认可用；Windows 需 `core.symlinks=true`，否则请改为直接复制 SKILL.md）。

## 安装

```bash
cd keyHunter
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # 填入 FOFA_KEY（可选 FOFA_EMAIL）
```

## 快速开始

```bash
# 基于 FOFA 结果的完整管道（Sub2API 默认查询）
keyhunter hunt --product sub2api --out results/run1

# 单个已知目标
keyhunter hunt --url http://HOST:8080 --out results/one

# 分步执行
keyhunter discover --product sub2api --out results/hits.json
keyhunter fingerprint --in results/hits.json --out results/alive.json
keyhunter spray --in results/alive.json --out results/sessions.json
keyhunter export --in results/sessions.json --out results/exports
keyhunter normalize --in results/exports --out results/artifacts
```

制品统一落在 `--out` 目录下（JSON 文件）。令牌只写入磁盘，CLI 只输出计数/套餐类型，不打印任何秘密。

## 目录结构

```text
keyHunter/
├── README.md
├── SKILL.md                 # 操作手册（技能）
├── docs/                    # API 与格式参考
├── keyhunter/               # Python 包 + CLI
│   └── data/                # 默认邮箱/密码字典（随包分发）
└── tests/
```

## 配置

| 环境变量 | 含义 |
|----------|------|
| `FOFA_KEY` | FOFA API 密钥（discover 必需） |
| `FOFA_EMAIL` | 可选，部分 FOFA 账号仍需要 |
| `FOFA_BASE_URL` | 默认 `https://fofa.info` |
| `FOFA_PAGE_SIZE` | 单页条数（默认 `100`） |
| `FOFA_MAX_PAGES` | 每个查询最大页数（默认 `3`） |
| `KEYHUNTER_PROXY` | 目标探测的可选 HTTP(S) 代理 |
| `KEYHUNTER_TIMEOUT` | 请求超时秒数（默认 `12`） |
| `KEYHUNTER_CONCURRENCY` | 指纹/撞库/导出的目标级并发（默认 `8`） |

## 产品

| id | 登录 | 导出 / 登录后接口 |
|----|------|--------------------|
| `sub2api` | `POST /api/v1/auth/login`（邮箱） | `/api/v1/admin/accounts/data` |
| `newapi` | `POST /api/user/login`（用户名） | `/api/token/` + IDOR `/api/token/{id}` |
| `oneapi` | 与 newapi 同族 | 同 token/channel 接口 |

支持别名：`new-api` → `newapi`，`one-api` → `oneapi`（`hunt` 全流程同样生效）。

### 撞库策略

- 凭据顺序：产品内置组合（`extra_credentials`）→ 按邮箱顺序，每个邮箱先跑完完整密码表再换下一个邮箱（Sub2API 主邮箱 `admin@sub2api.local` 优先）。
- 密码表 = 产品短名单 + 共享弱密码字典 `keyhunter/data/weak_passwords.txt`（约 489 条）。
- `--max-attempts` 默认**跑完整凭据计划**；传入数字可限制每个目标的尝试次数。
- 明确命中非管理员会话（`role` 非 admin）时会记录并**继续尝试**，不会拿普通会话冒充管理会话导出。

```bash
keyhunter products
keyhunter hunt --product newapi --out results/newapi1
keyhunter hunt --product oneapi --url http://HOST:3000 --out results/one
```

## 验证

```bash
# JWT 过期检查 + refresh_token 存在性（不做批量对话调用）
keyhunter validate --in results/artifacts --out results/valid.json
```

验证输出区分 `token_parseable` / `expiry_known` / `access_alive`：无法解析或过期未知的令牌不会被当作可用。

## 法律与合规声明

keyHunter 仅用于**学术研究**与**防御性安全**目的（识别、确认、修复安全暴露）。使用者必须遵守以下约束：

- **授权前提**：仅允许对您拥有、或已获得其所有者**明确书面授权**（注明范围、方式与时间）的系统、账户、网络或凭据使用本工具；
- **公开暴露不等于授权**：公网可访问、搜索引擎结果、公开报告中出现、或缺少访问控制提示，均不构成授权；
- **禁止行为**：禁止对任何未授权系统进行扫描、探测、访问、测试或利用；禁止对未授权凭据进行发现、验证、使用或留存；禁止绕过访问控制、速率限制、安全监控或服务条款；禁止撞库、暴力破解、钓鱼、恶意软件、拒绝服务或其他有害活动；
- **责任自负**：使用者对其使用行为承担全部法律责任（包括民事与刑事责任），并同意赔偿因违规使用造成的损失；
- **不提倡声明**：本项目不提倡、不鼓励任何未授权访问、凭据滥用或其他有害行为；项目作者与贡献者不对任何使用者的行为负责，亦不提供任何形式的保证（详见 [LICENSE](LICENSE) 第 10–12 条）。

完整条款见 [LICENSE](LICENSE)（keyHunter Defensive Security Source License v1.0）。

## 参考文档

- [操作手册（SKILL.md）](SKILL.md)
- [Sub2API API 参考](docs/reference-sub2api.md)
- [New-API / One-API 参考](docs/reference-newapi.md)
- [FOFA 查询参考](docs/reference-fofa.md)
- [制品格式参考](docs/reference-artifact-formats.md)
