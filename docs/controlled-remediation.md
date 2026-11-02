# Controlled Remediation

Validated findings become structured, simulated, human-approved change
proposals. Nothing executes against live Kong without a recorded approval
and an explicit server-side opt-in.

## Lifecycle

1. **Propose** — the remediation node builds one deterministic shell per
   eligible finding (exact service target, retrieved current config,
   allowlisted patch, diff, rollback plan). Findings without exactly one
   known missing plugin are skipped with a recorded reason.
2. **Draft prose** — one batched `remediation_planning` call drafts
   rationale, preconditions, consumer impact, breaking changes and
   validation plan. The prose validator accepts exactly those five keys;
   anything else (commands, URLs, config values) is rejected.
3. **Simulate** — the Security Fix Simulator applies the patch to an
   inventory copy, diffs the target and rescores the linked risk entry
   (residual risk). No I/O, no gateway writes.
4. **Approve** — `POST .../changes/<id>/approve` records reviewer, note
   and timestamp. Only `proposed` changes can move to `approved`.
5. **Execute** — `POST .../changes/<id>/execute` with `mode: live`
   re-validates, re-checks scope and approval, performs the single
   allowlisted call, then re-reads the plugin (post-change validation).
   Every refusal and failure is persisted on the proposal first.
6. **Roll back** — each proposal carries its deterministic inverse
   (`remove_plugin` for the plugin it enabled). Rollback executes only as
   its own approved change through the same adapter.

## Safety invariants

- v1 allowlist: `enable_plugin` with Kong default config only
  (`{"config": {}}`). Field-level config, consumer ops and any delete of
  services, routes or consumers are rejected by validation, not by prompt.
- Scope is the assessment's `service_names` (or the inventoried set);
  anything else is refused before any gateway call.
- The LLM never executes: no shell, no arbitrary HTTP, no direct writes.
  The adapter builds its own URLs from `KONG_ADMIN_API` and speaks only
  POST/GET/DELETE on `/plugins`.
- Live writes default off (`KONG_WRITE_ENABLED=false`). Simulation and
  validation always work.

## Statuses

`proposed → approved → executed → validated`, with `failed` recording the
exact error at whichever step broke (gate refusal, gateway error or
readback mismatch).

## API

- `GET /api/v1/ai-agents/assess/<id>/changes` — proposals with
  simulation and residual risk.
- `POST .../changes/<id>/approve` — `{"reviewer", "note"?}`.
- `POST .../changes/<id>/execute` — `{"mode": "simulate"|"live"}`.
  Refusals: 403 unapproved, 409 writes disabled, 400 invalid/out-of-scope,
  502 gateway failure. Failures persist on the proposal.

## Verification

- `backend/tests/test_changes.py` — shell derivation, exact-target
  rejection, prose smuggling rejection, validation gates, copy-only
  simulation, residual-risk math, approval and status marks.
- `backend/tests/test_kong_adapter.py` — unapproved/out-of-scope/invalid
  refusal with zero gateway calls, write-flag gate, success recording,
  failure accuracy, readback mismatch, gated rollback, URL guard.
- `backend/tests/test_orchestrator.py` — in-graph proposals with
  simulation, prose failure keeps the plan, approval/execute endpoint
  round-trip.
