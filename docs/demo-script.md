# Five-Minute Demo Script

Setup (before the clock): Redis Stack up, corpus ingested, `:5000` /
`:5001` / `:3000` running, operator key ready. Kong optional —
fallback inventory keeps the story intact; say so if it kicks in.

## 0:00–0:30 — The problem

"API estates drift: missing auth, no rate limits, stale inventory. Point
tools find plugins; nobody explains risk, and nobody lets you fix it
safely. This is a supervisor-led agent team that audits, explains, and
remediates Kong estates with a human in the loop."

## 0:30–1:30 — Live investigation

1. Sign in (operator key). Open **Investigation**, start a run on
   `OWASP API Top 10`.
2. Narrate the timeline as it fills: supervisor plan → discovery
   (call out live vs cached inventory) → three investigators in
   parallel → fan-in → risk scoring.
3. Expand one agent: model name (`muse-spark-1.3`), duration, decisions,
   tool calls. "Every event is a real backend trace entry."

## 1:30–2:30 — Risk, evidence, approval

4. Run pauses at the gate. Read the approval card: actions, risk levels.
5. Approve as a named reviewer. Open **Findings**: pick the top register
   entry, show factor rationales, merged sources, evidence refs.
6. Move one entry to `accepted` — lifecycle with actor recorded.

## 2:30–3:45 — Safe remediation

7. Open **Remediation Centre**. Pick a proposal: diff, consumer impact,
   breaking changes, residual risk (score drops), rollback plan.
8. Approve it, run **Simulate** — "zero gateway writes so far."
9. Attempt **Execute live**: blocked unless approved + admin + server
   flag. If pre-arranged against a dev gateway, execute one low-risk
   change and show the readback validation; otherwise show the refusal
   as the safety story. Either ending works.

## 3:45–4:30 — Why trust it

10. **Model Analytics**: routing table (all reasoning → Muse Spark),
    call log with latencies, one-click retrieval eval (hit rate 1.0).
11. "Deterministic code verifies, scores and gates; the model reasons
    and explains. Findings without evidence are quarantined, never
    shown as fact."

## 4:30–5:00 — Close

"Supervisor-led multi-agent audit, explainable risk, human-approved
remediation — running now, on our stack." Take questions.

## If something fails live

- LLM timeout: budgets degrade gracefully; show the degraded badge and
  the deterministic results that still landed.
- Kong unreachable: point at the provenance chip (snapshot + stale
  flag) — the fallback is a feature, demo it.
- Redis down: retrieval quarantines with explicit warnings; audit still
  completes on inventory evidence.
