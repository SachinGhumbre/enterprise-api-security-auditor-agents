# API Documentation

Base URLs: agents `:5000/api/v1/ai-agents`, knowledge `:5001/api/v1/knowledge`.
Auth (when keys are configured): `Authorization: Bearer <key>` or
`X-API-Key: <key>`. Roles: viewer (reads), operator (runs + approvals +
simulation), admin (ingest, deletes, live execution). Bodies are JSON;
errors are `{"error": "..."}` with HTTP status.

## Assessments (multi-agent)

| Method & path | Role | Purpose |
|---|---|---|
| `POST /assess[?async=true]` | operator | Start run. Body: `selected_standards`, `service_names`, `top_k`, `objective`, `priority_services`, `depth`, `risk_scoring`, `assessment_id?`. Sync: 202 + `approval_request` at the gate. Async: immediate `{"status": "running"}` |
| `GET /assess` | viewer | Recent-run index (newest first) |
| `GET /assess/<id>` | viewer | Status snapshot: agents, budgets, Kong provenance, summary, register digest |
| `GET /assess/<id>/details` | viewer | Full execution state for drill-down |
| `POST /assess/<id>/resume` | operator | Answer the gate: `{"decision": "approve"`, `"reviewer"`, `"note?"}`. Anything but approve rejects |
| `POST /assess/<id>/executive-summary` | operator | Board summary + risk narrative (completed runs) |
| `POST /assess/<id>/risk/<entry>/transition` | operator | Risk lifecycle: `{"to_state"`, `"actor?"`, `"note?"}` |
| `GET /assess/<id>/changes` | viewer | Change proposals with simulation + residual risk |
| `POST /assess/<id>/changes/<c>/approve` | operator | Record approval (`reviewer` required) |
| `POST /assess/<id>/changes/<c>/execute` | operator | `{"mode": "simulate"` (default) or `"live"` (admin + flag + approval) |

## Legacy single-agent

| Method & path | Role | Purpose |
|---|---|---|
| `POST /audit` | operator | Audit graph over Kong inventory |
| `GET /audit/report` | viewer | Last audit report |
| `POST /remediate` | operator | Remediation graph |
| `GET /remediate/plan` | viewer | Last remediation plan |
| `GET /kong/services` | viewer | Inventory with live/stale provenance |
| `GET /models` | viewer | Provider/model diagnostics |

## Model insight & eval

| Method & path | Role | Purpose |
|---|---|---|
| `GET /llm/calls?limit=` | viewer | Call records: model, task, latency, usage, retries, fallbacks (never bodies) |
| `GET /llm/policy` | viewer | Enforced task → provider/model/fallback table |
| `GET /eval/retrieval?store=fake\|redis` | viewer | Retrieval hit@k / MRR on demand |

## Knowledge (RAG)

| Method & path | Role | Purpose |
|---|---|---|
| `GET /health` | open | Status + non-secret config |
| `POST /index` | admin | Create/recreate the RediSearch index |
| `POST /ingest` | admin | Versioned ingest; per-file ingested/reindexed/skipped |
| `POST /search` | viewer | `{"query"` or `"finding"`, `"top_k?"`, `"filters?"}`, curated hits + sufficiency |
| `GET /stats` | viewer | Chunk counts by file |
| `GET /get_all_embeddings` | viewer | Paginated chunk dump |
| `DELETE /embeddings`, `DELETE /all_embeddings` | admin | Wipe vectors + manifest (aliases) |

## Health

`GET /health` on each service is open (load-balancer friendly) and returns
only non-secret configuration plus dependency warnings.
