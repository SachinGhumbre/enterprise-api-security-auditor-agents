# Policy Assessment Architecture

Deterministic, versioned control evaluation over discovered Kong evidence,
implemented in `backend/common/policy.py` and executed by the `compliance`
agent. Catalog version `1.0.0`; every result carries the catalog version, the
control version, the source document and retrieval references.

## Control groups

- **OWASP**: API2 authentication, API4 consumption, API9 inventory are
  evaluated; API1, API5, API8 need application/config evidence and report
  `not_evaluable` with the missing evidence named.
- **ISMS**: secure authentication and monitoring are evaluated; configuration
  management needs process evidence.
- **Authentication/authorisation**: strong-auth grading, authorisation
  presence; service mTLS needs caller topology.
- **Privacy**: audit trail and response minimisation are evaluated; processing
  security and log PII need storage/log evidence.
- **Encryption**: TLS transport and headers need protocol/certificate evidence.
- **Rate limiting**: rate limiting, bot detection and payload limits evaluated.
- **Logging**: audit logging, metrics and tracing evaluated.
- **Exposure**: network restriction evaluated; CORS and classification labels
  need config/label evidence.

## Honesty rules

- Checks return satisfied, partial, unsatisfied, or `not_evaluable`.
- `not_evaluable` always names the required evidence and appears in the gaps
  list, never as a finding.
- Only unsatisfied/partial results become findings, in the common schema.
- Policy findings are tier `suspected`: deterministic configuration gaps that
  still need human confirmation. The engine never claims a verified
  vulnerability.
- Unexpected check failures degrade to `not_evaluable`, never to a guess.

## Division of labour

- Deterministic code: control checks, grounding, coverage, tiers, scoring.
- Muse Spark 1.3: audit verdicts, conflict correlation, threat narratives,
  remediation plans, executive explanations (via the model router).
- Redis retrieval: policy excerpts ground controls (keyword match) and LLM
  verdicts (semantic search); matched chunk ids are preserved per finding.

## Common finding schema

Thirteen required fields: `finding_id`, `affected_api` (api + gateway
resource), `category`, `severity`, `confidence`, `evidence` (inventory facts
plus matched excerpt refs), `applicable_standard` (standard, control,
catalog version), `business_impact`, `attack_scenario`, `recommended_action`,
`validation_method`, `assessed_at`, `evidence_freshness` (retrieved_at, age,
stale flag). `build_finding()` rejects missing fields and bad enums.

## Coverage report

`compute_coverage()` aggregates per-domain and total counts plus a gaps list
(every unsatisfied, partial and `not_evaluable` control with its reason). The
compliance agent attaches it as `coverage`; the assessment summary and the
approval request carry it to reviewers.

## Verifying

- Unit: `python -m pytest backend/tests/test_policy.py -q`.
- Integration: compliance-node and graph coverage tests in
  `backend/tests/test_orchestrator.py`.
- Live: run an assessment, then read `coverage` in the summary or
  `coverage_totals` in the approval request.
