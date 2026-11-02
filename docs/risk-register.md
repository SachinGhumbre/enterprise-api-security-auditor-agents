# Enterprise Risk Register

The Risk Intelligence Agent consolidates the LLM security, policy and threat
finding streams into one deduplicated, scored, lifecycle-tracked register.
Scoring is deterministic and versioned; Muse Spark 1.3 only explains the
ranking.

## Pipeline

1. **Collect** — non-compliant LLM findings (`enriched_findings` +
   `recovered_findings`) plus every `policy_findings` entry. Threat
   scenarios stay hypotheses and do not enter the register as findings.
2. **Deduplicate** — findings sharing `(service, topic)` merge into one
   entry however many agents reported them. Topic derives from canonical
   Kong plugin names (authentication, rate limiting, logging, ...) or the
   policy control id (`OWASP-API2` → authentication, ...). Severity takes
   the max with the conflict recorded; confidence takes the
   best-supported claim; evidence unions.
3. **Correlate** — entries group by business capability (service-name
   family), and technical entries link to the compliance controls that
   fired on the same service and topic (`linked_controls`).
4. **Score** — six factors, each with a stated rationale (see below).
5. **Explain** — one `risk_reasoning` call (`llm_risk_explain` tool)
   narrates the ranking. If the model fails, the register still lands and
   the agent reports degraded.

## Scoring model v1.0.0

`score = weighted_mean(severity, exploitability, exposure, sensitivity,
criticality) × (0.6 + 0.4 × confidence / 10)`

Default weights: severity 0.30, exploitability 0.20, exposure 0.15,
sensitivity 0.15, criticality 0.20. Levels: ≥8.0 Critical, ≥6.0 High,
≥4.0 Medium, else Low.

| Factor | Inputs (score → rationale) |
|---|---|
| severity | Critical 10 / High 7.5 / Medium 5 / Low 2.5 |
| exploitability | strong auth 3 / weak-only auth 6 / no auth 9 / unknown service 5 |
| exposure | no routes 1 / network-restricted 4 / exposed routes 8 |
| sensitivity | priority service 8 / sensitive paths 7 / unlabelled 5 |
| criticality | priority service 9 / otherwise 4 |
| confidence | high 8 / medium 5 / low 2 — modulates, never re-ranks severity |

Every default is stated in its rationale (e.g. "unlabelled data; assumed
moderate"). Severity and confidence stay separate: a Critical/low-confidence
entry keeps severity Critical.

## Guarantees

- Unverified findings can never become verified entries; `verified` requires
  a confirmed tier, and the explainer prompt forbids upgrades.
- Every entry records `scoring_model` and `formula`, so old registers stay
  interpretable after the model changes.
- Overrides (`weights`, `blend_base`, `blend_scale`, `thresholds`) merge
  over the defaults per assessment via `POST /assess` `risk_scoring`; the
  version stamps whatever ran.

## Lifecycle

`open → accepted | mitigated | remediated`; `accepted → open | mitigated |
remediated`; `mitigated → open | remediated`; `remediated → open` (reopen).
Every move records actor, note and timestamp in `state_history`.

## API

- `GET /api/v1/ai-agents/assess/<id>` includes `risk_register`
  (scoring model, `by_state` counts, per-entry id/level/score/state).
- `POST /api/v1/ai-agents/assess/<id>/risk/<entry_id>/transition`
  with `{"to_state", "actor"?, "note"?}`; invalid moves return 400 naming
  the allowed next states. The rewrite goes through the workflow
  checkpointer, so snapshots and resume stay consistent.
- `POST /api/v1/ai-agents/assess/<id>/executive-summary` narrates the top
  register entries (risk reasoning) plus a board summary.

## Verification

- `backend/tests/test_risks.py` — dedup, cross-stream merge, exact formula
  math (8.3), config overrides, missing-context defaults, confidence
  modulation, unverified-never-verified, lifecycle, versioning, correlation.
- `backend/tests/test_orchestrator.py` — register shape/order in-graph,
  priority boost math (7.6), scoring overrides, explanation failure degrades
  gracefully, cross-stream merge, transition endpoint round-trip.
