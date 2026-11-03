# Setup & Deployment

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.11+ | Tested on 3.14 |
| Node.js | 18+ | Frontend build/dev |
| Docker Desktop | latest | Only for local Redis |
| Redis Stack | 7+ | Must include RediSearch |
| Meta Model API key | — | Required for reasoning |
| Kong Konnect / Gateway | — / 3.x | Optional; cached fallback exists |

## Install (PowerShell, repo root)

```powershell
# 1. Redis Stack
docker compose -f backend\docker-compose.yaml up -d

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

One command (repo root, venv activated) starts everything in order —
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
