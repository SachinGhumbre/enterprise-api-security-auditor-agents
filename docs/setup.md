# Setup & Deployment

## Prerequisites

**Option 1 (Docker) is recommended** — one command, identical on Windows,
macOS and Linux.

| Requirement | Option 1: Docker (recommended) | Option 2: Manual |
|---|---|---|
| Docker Desktop | latest — the only install | only for local Redis |
| Meta Model API key | **Required** — paste into `.env` | **Required** — paste into `backend/.env` |
| Kong Konnect / Gateway | Optional; blank = sample inventory | Optional; cached fallback exists |
| Python | not needed | 3.11+ (tested on 3.14) |
| Node.js | not needed | 18+, frontend build/dev |
| Redis Stack 7+ | bundled in the image | must include RediSearch |

## Install — Option 1: Docker (recommended)

```powershell
# 1. Create .env from the template (REQUIRED), then set META_API_KEY inside.
#    Kong is optional: leave KONG_ADMIN_API/KONG_ADMIN_TOKEN blank to audit
#    the bundled sample inventory.
copy .env.example .env   # macOS/Linux: cp .env.example .env

# 2. Build and start the whole stack (Redis + 3 APIs + dashboard)
docker compose up -d --build

# 3. Open http://localhost:3000, sign in with operator / operator
```

`.env` changes apply with `docker compose restart` (no rebuild).
First boot auto-ingests the policy corpus; watch `docker compose logs -f`.

## Install — Option 2: Manual (PowerShell, repo root)

```powershell
# 1. Redis Stack
docker compose -f backend\docker-compose_redis.yaml up -d

# 2. Python env
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cd ..

# 3. Configure backend\.env (see docs/environment.md), at minimum:
#    META_API_KEY, REDIS_HOST, ADMIN_API_KEYS / OPERATOR_API_KEYS
python backend\scripts\verify_meta.py

# 4. Frontend
cd frontend
npm install
cd ..
```

## Run

Docker: `docker compose up -d` to start, `docker compose down` to stop,
`docker compose restart` after `.env` edits.

Manual: one command (repo root, venv activated) starts everything in order —
Redis harness, knowledge API, agents API, then the dashboard — waiting
for each Python service to answer its health endpoint first. Services
already running are detected and skipped.

```powershell
.\backend\.venv\Scripts\Activate.ps1
python start_all.py
# Options: --skip-redis-test, --skip-frontend, --timeout 90
```

Or manually, one window per service:

```powershell
python redis-test.py                    # :5002  Redis harness (optional)
python backend\rag\knowledge_ingestor.py  # :5001
python backend\agents\init_auditor.py     # :5000
cd frontend; npm start                   # :3000
```

## First run

(Docker auto-ingests on first boot; manual installs run the ingest step
below explicitly.)

```powershell
# Health (open endpoints, no key needed)
curl http://localhost:5001/api/v1/knowledge/health
curl http://localhost:5000/api/v1/ai-agents/health

# Ingest the versioned policy corpus (admin key)
curl -X POST http://localhost:5001/api/v1/knowledge/ingest `
  -H "Content-Type: application/json" -H "X-API-Key: <admin>" `
  -d '{"reset": true}'

# Start an agentic assessment (operator key), then follow it
curl -X POST "http://localhost:5000/api/v1/ai-agents/assess?async=true" `
  -H "Content-Type: application/json" -H "X-API-Key: <operator>" `
  -d '{"selected_standards": ["OWASP API Top 10"]}'
# → {"assessment_id": "...", "status": "running"}
# Poll GET /api/v1/ai-agents/assess/<id> until awaiting_approval,
# then POST .../resume {"decision": "approve", "reviewer": "..."}.
```

Or do all of this from the dashboard's Investigation page.

## Deployment notes

- Bind Flask to localhost unless behind an authenticated reverse proxy;
  set API keys and `ALLOWED_ORIGINS` for anything networked.
- The assess run index, async threads, LLM call log and checkpointer are
  in-process: single worker, restart loses them. Redis data and
  `backend/artifacts/` persist.
- Ship `backend/artifacts/audit.log.jsonl` to central storage for
  production evidence; the local chain detects modification, not
  truncation or a second writer.
- Never enable `KONG_WRITE_ENABLED=true` against production without a
  change window; default is simulation only.
- Re-run `pip-audit -r backend/requirements.txt` on every dependency
  change (not run in this sandbox; see docs/application-security.md).
- The Docker container is the same single-worker topology in a box:
  restart loses in-flight runs and the run index; the Redis volume and
  `backend/artifacts/` persist.
