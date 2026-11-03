# Model Routing Policy

All reasoning calls go through `backend/common/router.py` with an explicit task
type. Agents never select models themselves, and no call relies on a CLI or API
default: an empty model id raises instead of guessing.

## Principles

- Muse Spark 1.3 (`META_MODEL`) is the primary engine for every reasoning task.
- Scoring, rule evaluation and verification stay deterministic in `rules.py`.
- Azure OpenAI keeps embeddings and serves as optional, configured fallback only.
- Fallback is observable: every skip, retry and fallback lands in the call log.
- Auth, malformed-request and unknown-model errors never retry or fall back.

## Per-task policy

### security_investigation

- Complexity: high. Provider: Meta, model `META_MODEL`.
- Reason: per-service verdicts need strict structured JSON.
- Used by: Audit Agent, `security_analysis` investigator.

### evidence_correlation

- Complexity: high. Provider: Meta, model `META_MODEL`.
- Reason: reconciling cross-agent conflicts needs contextual evidence reasoning.
- Used by: `followup` loop, once per pass, only while conflicts stay unresolved.

### threat_modelling

- Complexity: high. Provider: Meta, model `META_MODEL`.
- Reason: narratives must stay grounded in the deterministic control catalog.
- Used by: `threat_model` investigator (single narrative call).

### risk_reasoning

- Complexity: high. Provider: Meta, model `META_MODEL`.
- Reason: explaining top risks needs context; numeric scores stay in code.
- Used by: executive-summary endpoint (on demand, completed runs only).

### remediation_planning

- Complexity: high. Provider: Meta, model `META_MODEL`.
- Reason: fix plans need the strict ten-field schema with real citations.
- Used by: Remediation Agent, batched per `REMEDIATION_BATCH_SIZE`.

### executive_explanation

- Complexity: medium. Provider: Meta, model `META_MODEL`.
- Reason: board summaries need faithful abstraction without new claims.
- Used by: executive-summary endpoint (on demand, completed runs only).

### assistant_intent

- Complexity: medium. Provider: Meta, model `META_MODEL`.
- Reason: ambiguous chat messages need instruction-following
  classification into a strict intent JSON schema.
- Used by: assistant graph `interpret` step (only for ambiguous input;
  clear intents classify deterministically).

### assistant_qa

- Complexity: high. Provider: Meta, model `META_MODEL`.
- Reason: security explanations must reason over retrieved policy
  evidence and inventory facts without inventing claims.
- Used by: assistant knowledge/investigation answers.

### assistant_synthesis

- Complexity: high. Provider: Meta, model `META_MODEL`.
- Reason: cross-agent results need faithful synthesis with evidence
  citations and no invented execution claims.
- Used by: assistant graph `synthesize` step; deterministic rendering
  when the model is unavailable.

## Fallback rules

- Order comes from `LLM_FALLBACK_ORDER` (`none` by default; e.g. `azure`).
- Only retryable errors fall back: timeouts, connection errors, HTTP 429/5xx.
- `401/403`, malformed requests and `model_not_found` raise immediately.
- `META_ONLY=true` (default) blocks non-Meta fallback; the skip is recorded.
- Unconfigured fallback entries are skipped with a recorded reason.
- The winning response carries `fallback_used`, `fallback_reason` and `skipped`.

## Resilience

- Bounded retries per candidate (`ROUTER_MAX_RETRIES`, default 2) with
  exponential backoff; timeouts from `LLM_TIMEOUT`.
- Per-model circuit breaker (`CIRCUIT_THRESHOLD`/`CIRCUIT_COOLDOWN_S`);
  open circuits skip the candidate observably, then half-open probe.
- Streams (`run_stream`) are single-attempt; guarded calls use `run()`.

## Log safety

- The call log stores model, task, latency, usage, retries and fallback events.
- Prompt/response bodies are never logged, only character counts.
- Recorded error text passes through `redact()` (bearer tokens, API keys,
  passwords, `sk-`/`kpat_` shapes).

## Verifying the selected model in a trace

1. `GET /api/v1/ai-agents/llm/calls` — every call lists `provider`, `model`,
   `task`, `retries` and `fallback_used`.
2. Agent records (`agents.<name>.model`, `tool_calls`) in the assessment state.
3. `assessment_summary.budgets` plus the persisted `*_assessment.json` artifact.
4. Eval reports record the exact model string per task row.

## Evaluation

`python backend/eval/run_eval.py --compare mock:good mock:weak` runs the offline
harness check (deterministic judges, no keys). Live runs use `--compare meta
azure` and need `META_API_KEY` plus the Azure endpoint/key/deployment with
`META_ONLY=false`.

Latest measured harness check (mock exemplars, proves discrimination only):

- mock:good — 6/6 passed, avg score 1.000.
- mock:weak — 0/6 passed, avg score 0.561.

No live model comparison has been measured in this environment, so no claim is
made about either model being better. Run the live comparison to obtain one.
