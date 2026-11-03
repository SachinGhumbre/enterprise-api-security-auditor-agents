# Application Security

What this hardening phase added, what was already sound, and what remains
open. Passing checks do not constitute compliance or complete security;
treat this as a baseline, not a certification.

## Authentication and roles

- API-key auth (`common/auth.py`) on both Flask apps, disabled when no
  keys are configured (single-user default). Keys via
  `Authorization: Bearer` or `X-API-Key`, compared in constant time.
- Roles: **viewer** (read-only + knowledge search), **operator** (run and
  resume assessments, approve changes, simulate, manage the risk
  register), **admin** (ingest, index management, deletes, live
  execution). Health endpoints stay open for load-balancer probes.
- UI: demo username/password sign-in (`admin` / `operator` / `viewer`,
  passwords from `frontend/.env`, shown on the login page). Each account
  maps to that role's API key and is verified against the backend before
  entering; keys live in sessionStorage (tab lifetime) with an optional
  `REACT_APP_API_KEY` build-time fallback. A 401 mid-session signs out
  with a notice. The password check is demo UX only — role enforcement
  stays server-side via the mapped key.
- CORS preflights (`OPTIONS`) bypass auth by design: browsers send them
  without credentials and they return no data. The real request still
  authenticates; without the bypass, key-based dashboard calls fail.
- Configure: `ADMIN_API_KEYS`, `OPERATOR_API_KEYS`, `VIEWER_API_KEYS`
  (comma-separated), `ALLOWED_ORIGINS` for CORS.

## Previously sound, now pinned by tests

- Tool permissions enforced outside the LLM (gateway allowlists),
  least-privilege per agent.
- Approval semantics: unknown governance answers resolve to reject;
  unapproved/out-of-scope/invalid changes cannot execute; risk
  transitions follow a strict state machine; assessment ids cannot be
  reused to fork a run.
- Secrets: env-only, boolean-only in `config.summary()`, redacted from
  router error logs. `.env` files are gitignored.
- Retrieved policy text treated as untrusted (delimited excerpts +
  grounding rules); gateway-derived names/paths are now flattened to
  single prompt lines before interpolation.
- Deterministic gates (verification, budgets, validation, scoring) run
  in code; the model cannot override them.

## New in this phase

- `common/validation.py`: shapes, enums, bounds and length caps on
  every mutating payload (400s, not 500s); traversal guard on ingest
  roots; 16 MB request cap (413) on both apps.
- `common/audit_log.py`: append-only hash-chained JSONL log
  (`assessment.*`, `risk.transition`, `change.approved/simulated/
  executed/execution_refused`, `knowledge.*`). `verify()` detects
  modification; actors are roles + key fingerprints, never keys.
- Redis ACL username support (`REDIS_USERNAME`); use a least-privilege
  Redis user and a read-only Kong RBAC token in production.

## Residual risks

1. **No per-tenant isolation.** Any valid key sees every assessment;
   assessment ids are unguessable but bearer-equivalent. Single-team
   deployment only.
2. **No rate limiting.** Expensive endpoints (assess, ingest) are one
   request away from full LLM/Kong spend. Put a reverse proxy with
   throttling in front for any exposed deployment.
3. **Audit log is local.** Tail truncation is not self-detectable and a
   second writer/host diverges the chain; ship lines centrally for
   production evidence.
4. **XSS steals UI keys.** Standard SPA exposure: a script injection
   could read the sessionStorage key. Mitigate with CSP headers at the
   static host (not set by this repo).
5. **Single-user default is open.** Forgetting to set keys leaves every
   endpoint (except live Kong writes, still flag-gated) reachable on the
   network. Bind to localhost or set keys.
6. **Write adapter shares the Kong token.** Discovery wants read-only
   credentials, but live execution reuses `KONG_ADMIN_TOKEN`; Kong RBAC
   cannot split them per endpoint here. Prefer Konnect RBAC roles that
   match your intent.
7. **Dependency review is point-in-time.** See below; re-run on every
   dependency change, ideally in CI.

## Dependency review

Installed versions at review time (Python 3.14):

- Flask 3.1.3, flask-cors 6.0.5, langgraph 1.2.19, redis 8.1.0,
  numpy 2.5.4, openai 3.42.0, requests 2.34.2, urllib3 2.8.0,
  python-dotenv 1.2.4, truststore 0.10.5, pytest 9.2.0.

Automated OSV scan was not run: `pip install pip-audit` hung in this
sandbox and was terminated rather than risk environment corruption
(verified healthy afterwards). Before any exposed deployment, run
`pip-audit -r backend/requirements.txt` from a networked shell and
record the result here. No dependency is pinned to a known-bad version
as far as a version-level review shows, but that is not a substitute
for the scan.

## Verification

- `test_auth.py` — disabled-mode passthrough, key identification,
  per-app role matrix, live-execute admin gate, Redis username.
- `test_validation.py` — coercions, endpoint 400s, id-reuse 409,
  traversal block, body cap.
- `test_audit_log.py` — chain roundtrip, tamper detection, actor
  labels, prompt flattening at two prompt sites.
- `test_orchestrator.py` — invalid approval resolves to reject, audit
  event emission, refusal auditing.
- `test_ingestion.py` — knowledge mutation auditing.
- `frontend/src/api/client.test.js` — key header, signed-out mode,
  401 hook, storage roundtrip.
