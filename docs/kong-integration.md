# Kong Integration

Enterprise-scale, read-only Kong discovery for Konnect and self-managed
Admin APIs, with resilience, provenance and change detection.

## Resolution order

Every inventory read resolves `live → Redis snapshot → cached file`:

1. **Live** — per-collection GET with bounded retries (429 honors
   `Retry-After` within `KONG_RETRY_MAX_WAIT_S`; 5xx/timeouts/
   connection errors retry with backoff; TLS and auth errors never
   retry). A services failure is fatal; routes/plugins failures degrade
   to a partial inventory with explicit `gaps`.
2. **Redis snapshot** — last successful snapshot with `captured_at`,
   `source`, `environment` and freshness (`KONG_SNAPSHOT_STALE_S`,
   default 1h). Missing, corrupt or unreachable cache falls through.
3. **Cached file** — shipped fallback, always treated as stale
   (unknown capture time).

Successful live reads re-cache the snapshot (previous kept for diffing).

## Provenance (never cached-as-live)

Discovery records `kong_source`, `kong_live`, `kong_stale`,
`kong_snapshot_at`, `kong_gaps`, `kong_capabilities` and `kong_changes`.
Non-live runs degrade explicitly ("not a live assessment"). The assess
status endpoint, the final summary and the per-assessment `inventory`
artifact all carry the same provenance.

## Change detection

Live reads diff against the previous snapshot: services added/removed,
per-service plugins added/removed, routes added/removed. Lists cap at 50
entries with overflow counts.

## Capability probing

No environment is assumed to expose identical APIs. Core collections
degrade per-collection; optional collections (consumers) are best-effort
and recorded in `kong_capabilities` as supported/unsupported.

## Separation

Discovery is GET-only (`common/kong_inventory.py` has no write path;
tested). All mutation lives in `common/kong_adapter.py` behind approval
and `KONG_WRITE_ENABLED`. Use a read-only RBAC token for
`KONG_ADMIN_TOKEN`; the write adapter needs no separate credential
because it reuses the same token only when explicitly enabled.

## API

- `GET /api/v1/ai-agents/kong/services` — inventory with `live`,
  `stale`, `snapshot_at` and `gaps`.
- `GET /api/v1/ai-agents/assess/<id>` — `kong` provenance block.

## Configuration

`KONG_MAX_RETRIES` (2), `KONG_RETRY_BACKOFF_S` (1),
`KONG_RETRY_MAX_WAIT_S` (5), `KONG_SNAPSHOT_KEY`
(`kong:snapshot:latest`), `KONG_SNAPSHOT_STALE_S` (3600).

## Verification

- `test_kong_client.py` — flavours, pagination, retry/429/timeout
  behaviour, TLS no-retry, HTTP-layer read-only proof.
- `test_kong_inventory.py` — partial collect, snapshot roundtrip/
  staleness/corruption/outage, diffing, capability probes.
- `test_kong_integration.py` — mocked Konnect flow end to end, discovery
  node on real tools, partial survival, endpoint live→snapshot
  transition, write-path separation.
