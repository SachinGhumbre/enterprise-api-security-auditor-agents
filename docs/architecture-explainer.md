# Three-Minute Architecture Explanation

(Talk track for judges. Diagram: `docs/architecture.md`.)

## Minute 1 — The shape (0:00–1:00)

"Three processes and two external systems. A React dashboard; an agents
API running a LangGraph supervisor graph with nine agents; a knowledge
service doing versioned RAG over Redis Stack. The graph reads Kong
through a read-only Admin API integration and reasons through Meta's
Model API on Muse Spark 1.3. State checkpoints per assessment, and every
security-relevant event lands in a hash-chained audit log. A floating
copilot on every page chats over the same APIs."

"The key structural decision: the model proposes, code disposes.
Verification, risk scoring, budgets, approvals and the Kong write
adapter are all deterministic Python outside the LLM. The model can be
wrong; the gates can't be talked past."

## Minute 2 — A run (1:00–2:00)

"An assessment starts validated and role-checked. The supervisor writes
an investigation plan with stopping criteria, then dispatches. Discovery
pulls inventory with live-to-snapshot-to-file fallback, each step
stamped with provenance, so cached data is never presented as live.
Security, compliance and threat agents investigate in parallel and fan
in; a bounded follow-up loop chases missing evidence or conflicts."

"Risk intelligence deduplicates everything into one register with a
versioned scoring formula — every factor keeps its rationale — then the
remediation agent drafts structured change proposals with diffs,
simulations and residual risk. Validation checks the plan, governance
pauses for a human, and only approved changes can execute through an
allowlisted adapter that re-reads the gateway afterwards to prove the
result."

## Minute 3 — Why it's enterprise, not demo-ware (2:00–3:00)

"Four things I'd point at. One: evidence discipline — findings without
retrieved evidence are quarantined, never asserted; unverified never
becomes verified. Two: failure honesty — every fallback degrades
explicitly with a badge and a reason, from stale inventory to model
outages. Three: least privilege end to end — per-agent tool allowlists,
API roles, and a write path that defaults to simulation. Four:
measurement — 378 backend tests, retrieval hit rate 1.0 on a curated
set, and a routing table you can inspect live that pins every reasoning
task to Muse Spark 1.3."

"Happy to go deeper on any layer."
