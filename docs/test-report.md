# Test & Evaluation Report

Measured on this machine, Python 3.14 + Node 18+, immediately before the
hackathon. Sandbox limits are stated, not hidden.

## Automated suites

| Suite | Result | Notes |
|---|---|---|
| Backend (`pytest backend/tests`) | **296 passed, 0 failed** | ~11s. Covers all 9 agents, router, policy, threats, risks, changes, Kong adapter/inventory, RAG, auth, validation, audit log |
| Frontend (`react-scripts test`) | **4 passed** | API-key header, signed-out mode, 401 hook, storage roundtrip |
| Frontend build (`npm run build`, CI) | **Compiles** | ESLint-clean, 83 kB gzipped JS |
| Flask construct smoke | **21 + 9 routes** | Both apps build their route maps |

## Retrieval eval (offline, deterministic)

`python backend/eval/run_retrieval_eval.py --store fake` over the real
corpus files:

- **hit_rate 1.0, MRR 0.95** (10 tasks, 9 at rank 1).
- Gated by `test_retrieval_eval.py`: corpus changes must keep it green.
- The live-index variant (`--store redis`) needs ingest + Redis Stack and
  was not run here.

## Model eval (mock transports, deterministic)

`python backend/eval/run_eval.py --compare mock:good mock:weak`, 6 tasks:

- mock:good **6/6, avg 1.000**; mock:weak **0/6, avg 0.561**.
- Proves the judge discriminates; it says nothing about Muse Spark vs
  any fallback. A live `meta` vs `azure` comparison needs keys +
  network and was not run — no superiority claim is made.

## Scenario coverage (38 security tests)

- Approval: unknown answers reject; unapproved/out-of-scope/invalid
  changes cannot execute; refused executions are audited.
- Resilience: Kong outage → snapshot → file; partial collections;
  429/5xx/timeout retries; Redis down; empty retrieval quarantine.
- Integrity: audit tamper detection, delete-manifest consistency,
  prompt flattening of hostile names, injection-delimited excerpts,
  traversal and body-cap rejection, id-reuse 409.

## Not verified here

- Real port binds (sandbox denies listening sockets), live Redis Stack,
  live Kong Admin API, live Meta inference, and the `meta` vs `azure`
  eval comparison. Verify these on the demo machine with
  `docs/setup.md`, then re-run the two eval commands above.
