# Environment Reference

**Docker (recommended):** everything is read from the single root `.env`
(copy `.env.example`, set `META_API_KEY`) — the container mounts it to
`/app/backend/.env`, dashboard Section 7 included. It is never baked into
the image. **Manual:** backend settings come from `backend/.env`
(absolute path, any launch directory) and dashboard settings from
`frontend/.env`. Generated from `backend/common/config.py`; defaults shown.

## Auth & access

| Variable | Default | Purpose |
|---|---|---|
| `ADMIN_API_KEYS` | _(none)_ | Full access (ingest, deletes, live execute) |
| `OPERATOR_API_KEYS` | _(none)_ | Run/approve/simulate |
| `VIEWER_API_KEYS` | _(none)_ | Read-only |
| `ALLOWED_ORIGINS` | _(none)_ | CORS allowlist; unset = `*` |
| `REDIS_USERNAME` | _(none)_ | Redis ACL username |
| `REDIS_PASSWORD` | _(none)_ | Redis password |

No keys anywhere = single-user mode (all endpoints open).

## Redis & vectors

| Variable | Default | Purpose |
|---|---|---|
| `REDIS_HOST` / `REDIS_PORT` | `localhost` / `6379` | Redis Stack |
| `INDEX_NAME` / `KEY_PREFIX` | `security_auditor_index` / `embedding:` | Index scope |
| `VECTOR_DIMENSIONS` | `1536` | Must match the embedding model |

## Knowledge base

| Variable | Default | Purpose |
|---|---|---|
| `KNOWLEDGE_BASE_DIR` | `knowledge_base` | Corpus dir under `backend/` |
| `CHUNK_SIZE` / `CHUNK_OVERLAP` | `900` / `120` | Word-boundary chunking |

## Meta Model API (primary reasoning)

| Variable | Default | Purpose |
|---|---|---|
| `META_API_KEY` (or `MODEL_API_KEY`) | _(none)_ | Required for live reasoning |
| `META_MODEL` | `muse-spark-1.3` | Explicit model id; empty refuses to call |
| `META_BASE_URL` | `https://api.meta.ai/v1` | OpenAI-compatible endpoint |
| `LLM_PROVIDER` | `auto` | `meta` / `kong` / `auto` |
| `META_ONLY` | `true` | Forbid non-Meta reasoning providers |
| `LLM_FALLBACK_ORDER` | `none` | Opt-in fallback chain |
| `LLM_TIMEOUT` / `LLM_MAX_TOKENS` | `120` / `8000` | Per-call bounds |
| `ROUTER_MAX_RETRIES` | `2` | Bounded retries |
| `CIRCUIT_THRESHOLD` / `CIRCUIT_COOLDOWN_S` | `5` / `60` | Circuit breaker |
| `REMEDIATION_BATCH_SIZE` | `5` | Findings per planning call |

## Embeddings

Retrieval vectors are produced locally (deterministic hashed bag-of-words
over `VECTOR_DIMENSIONS`); there is no embedding provider to configure.

## Kong discovery (read-only)

| Variable | Default | Purpose |
|---|---|---|
| `KONG_ADMIN_API` | _(none)_ | Admin API base (Konnect needs `/v2/control-planes/<id>`) |
| `KONG_ADMIN_TOKEN` | _(none)_ | Konnect PAT or self-managed token |
| `KONG_ADMIN_MODE` | `auto` | `auto` / `konnect` / `onprem` |
| `KONG_ADMIN_VERIFY_SSL` | Konnect `true`, else `false` | TLS verification |
| `KONG_PAGE_SIZE` / `KONG_HTTP_TIMEOUT` | `1000` / `30` | Listing behaviour |
| `KONG_MAX_RETRIES` / `KONG_RETRY_BACKOFF_S` / `KONG_RETRY_MAX_WAIT_S` | `2` / `1` / `5` | Transient-failure retries |
| `KONG_SNAPSHOT_KEY` / `KONG_SNAPSHOT_STALE_S` | `kong:snapshot:latest` / `3600` | Redis snapshot cache |

## Kong writes (gated remediation)

| Variable | Default | Purpose |
|---|---|---|
| `KONG_WRITE_ENABLED` | `false` | Live execution master switch |
| `KONG_AI_PROXY_HOSTNAME` / `KONG_API_KEY` | _(none)_ | Optional AI Gateway LLM route |

## AI Assistant (chat copilot)

| Variable | Default | Purpose |
|---|---|---|
| `ASSISTANT_CONV_TTL_S` | `2592000` (30 days) | Conversation history retention in Redis |
| `ASSISTANT_MAX_MESSAGES` | `200` | Stored messages per conversation (cap) |
| `ASSISTANT_CONTEXT_MESSAGES` | `20` | Recent messages sent as model context |
| `ASSISTANT_SUMMARY_THRESHOLD` | `40` | Messages before rolling summarization kicks in |
| `ASSISTANT_MAX_TOOL_CALLS` | `8` | Tool calls allowed per chat turn |
| `ASSISTANT_LLM_BUDGET` | `4` | Model calls allowed per chat turn |

## Misc

| Variable | Default | Purpose |
|---|---|---|
| `ARTIFACT_DIR` | `backend/artifacts` | Reports, snapshots, audit log |
| `AGENTS_PORT` / `KNOWLEDGE_PORT` | `5000` / `5001` | Service ports (test harness is fixed at `5002`) |

Frontend — Docker: Section 7 of the root `.env`, injected into the UI at
container startup (`docker compose restart` applies edits, never a
rebuild). Manual (`frontend/.env`, gitignored; see `frontend/.env.example`):
`REACT_APP_AGENTS_URL`, `REACT_APP_KNOWLEDGE_URL`,
`REACT_APP_REDIS_TEST_URL`, `REACT_APP_API_KEY` (build-time fallback;
sign-in preferred), plus demo login `REACT_APP_{ADMIN,OPERATOR,VIEWER}_PASSWORD`
(shown on the login page) and `REACT_APP_{ADMIN,OPERATOR,VIEWER}_KEY` (must
match the backend role keys; never displayed).
