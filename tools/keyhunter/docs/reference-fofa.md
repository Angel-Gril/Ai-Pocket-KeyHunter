# FOFA reference

## API search

```text
GET {FOFA_BASE_URL}/api/v1/search/all
```

| Param | Meaning |
|-------|---------|
| `key` | API key |
| `email` | Optional account email |
| `qbase64` | Base64 of the query string (UTF-8) |
| `page` | 1-based page |
| `size` | page size |
| `fields` | comma-separated columns |

keyHunter default fields:

```text
host,ip,port,protocol,title,header,banner,server,product,link,domain,cert
```

## Query language (subset)

| Syntax | Example |
|--------|---------|
| Body contains | `body="sub2api"` |
| Title | `title="Sub2API"` |
| Port | `port="8080"` |
| AND / OR | `&&` / `\|\|` |
| Country exclude | `country!="CN"` |
| Protocol | `protocol="http"` |

## Sub2API starter set

```text
body="sub2api" && port="8080"
body="sub2api" || title="Sub2API"
title="Sub2API" && port="8080"
```

## Tips

1. Prefer API key over cookie scraping.
2. Dedupe by `(ip, port)` and normalized origin.
3. Prefer `link` / `host` when present.
4. Respect rate limits (`FOFA_PAGE_SIZE`, `FOFA_MAX_PAGES` in `.env`).
