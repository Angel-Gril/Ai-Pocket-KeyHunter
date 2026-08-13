# Artifact formats

## CPA / Codex session

| Field | Notes |
|-------|-------|
| `type` | e.g. `codex` |
| `email` / `name` | account email |
| `account_id` | UUID |
| `chatgpt_account_id` | UUID |
| `plan_type` / `chatgpt_plan_type` | `plus` / `pro` / … |
| `access_token` | JWT |
| `refresh_token` | opaque |
| `id_token` | JWT |
| `expired` | ISO-8601 |
| `disabled` | bool |

## Sub2API export document

```json
{
  "exported_at": "<iso8601>",
  "proxies": [],
  "accounts": [
    {
      "name": "<email>",
      "platform": "openai",
      "type": "oauth",
      "expires_at": 1780473960,
      "credentials": {
        "access_token": "...",
        "refresh_token": "...",
        "chatgpt_account_id": "...",
        "email": "...",
        "plan_type": "plus"
      }
    }
  ]
}
```

## Mapping (Sub2API export → CPA)

| Sub2API | CPA |
|---------|-----|
| `credentials.access_token` | `access_token` |
| `credentials.refresh_token` | `refresh_token` |
| `credentials.id_token` | `id_token` |
| `credentials.email` or `name` | `email`, `name` |
| `credentials.chatgpt_account_id` | `chatgpt_account_id` / `account_id` |
| `credentials.plan_type` | `plan_type`, `chatgpt_plan_type` |
| JWT `exp` / `expires_at` | `expired` |
| constant | `type: "codex"` |

## keyHunter finding record

Each normalized finding is also summarized as:

```json
{
  "product": "sub2api",
  "origin": "http://host:8080",
  "email": "user@example.com",
  "plan_type": "pro",
  "has_refresh": true,
  "expired": "2026-08-06T17:49:45+00:00",
  "artifact": "artifacts/cpa/user_example_com.json",
  "fingerprint": "<sha256 of access_token>"
}
```

High-value heuristic: `plan_type` ∈ {`pro`,`team`,`enterprise`} OR refresh present OR expiry > 7 days.
