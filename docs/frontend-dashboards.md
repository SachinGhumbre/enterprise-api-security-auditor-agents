# Frontend Dashboards

Multi-agent visibility added to the existing React/Tailwind dashboard.
Same design system (`components/ui.jsx`), same API client, no mock data:
every number renders from a backend response or an explicit empty state.

## Pages

- **Overview** — service health (unchanged) plus recent assessments
  (newest first, click through to Investigation).
- **Investigation** — start an async run (standards, depth, objective,
  services), then follow it live: pipeline progress, supervisor plan,
  per-agent timeline (status, model, duration, retries, decisions, tool
  calls, errors), budgets, Kong provenance, warnings, raw trace, and an
  inline approval gate. Polls `details` every 2s while running; stops on
  pause/complete/fail. Attach to any id, so long runs survive navigation.
- **Findings & Evidence** — risk register with factor rationales,
  evidence, merge sources and lifecycle moves; security, policy and
  threat streams; quarantine banner; on-demand executive summary.
- **Remediation Centre** — change proposals with diff, rationale,
  impact, residual risk, simulation and rollback; approve / simulate /
  live-execute (confirm dialog; backend still enforces role + flag +
  approval); plan export decision.
- **Model Analytics** — routing policy table, call log with latency /
  tokens / retries / fallbacks, aggregates, and one-click retrieval
  eval (fake or redis store).

## Backend enablers (all additive)

- `POST /assess?async=true` — background run, immediate 202; failures
  surface as `failed` on status polling.
- `GET /assess` — recent-run index (in-memory, capped).
- `GET /assess/<id>/details` — full execution snapshot for drill-down.
- `GET /llm/policy` — enforced routing table.
- `GET /eval/retrieval?store=` — hit@k / MRR on demand.
- Resume while a run is active returns 409 instead of racing the thread.

## Run it

```bash
cd frontend && npm start   # http://localhost:3000
```

Needs the agents API on :5000 (and :5001 for knowledge features).
Sign in with an API key when the backends enforce auth, or leave the
key empty in single-user mode.

## Limits

- Polling, not streaming: 2s granularity; concurrent `get_state` reads
  during an async run can lag the writer by a checkpoint.
- The run index and async threads are in-process (lost on restart,
  single worker only).
- `details` returns the whole state; very large estates make heavy
  polls — refresh manually instead of following live in that case.
