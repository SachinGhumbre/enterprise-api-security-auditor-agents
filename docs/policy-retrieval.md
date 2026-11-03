# Policy Retrieval (RAG)

Redis Stack + RediSearch remains the retrieval infrastructure: no concrete
limitation was found in it. The weakness was curation, not the engine -
this phase adds versioning, filtering, verification and measurement.

## Corpus

`backend/knowledge_base/` holds six policy documents plus the Kong mapping
guide (`ALL/` mirrors the policies and is skipped at ingest). Each policy
carries front-matter:

```
Policy-Name: Authentication Policy
Policy-Version: 1.0
Effective-Date: 2025-01-15
Category: authentication
Applies-To: all
```

Missing headers fall back to `vX.Y` regex (version), filename signals
(category) and `all` (scope). Nothing else is guessed.

## Ingestion

`POST /api/v1/knowledge/ingest` (ingestor service, default port 5001):

- Chunking: word-boundary splits with overlap (`CHUNK_SIZE` 900,
  `CHUNK_OVERLAP` 120).
- Deterministic chunk ids (`sha1(filename, index, content)`): re-ingesting
  unchanged content rewrites the same keys instead of duplicating.
- A Redis manifest (`kb:manifest`) records per-file content hash, version
  and chunk count. Unchanged files are skipped; changed files have their
  old chunks deleted and are re-ingested (`action: ingested | reindexed |
  skipped` per file). `reset=true` wipes chunks and the manifest.
- The embedding space (`kb:embedding`: provider, model, dimensions) is
  stamped at ingest. `search()` fails closed on a mismatch with a
  re-ingest pointer; legacy indexes without a record still read.

Index and query always share one embedding configuration (local vectors
over `VECTOR_DIMENSIONS`); the check above enforces it instead of
trusting it.

## Retrieval

`vector_store.search(query, top_k, filters)` over cosine KNN:

- Filters: `category`, `policy_version`, `applies_to`,
  `effective_as_of`, `include_superseded`, `include_not_effective`.
  Oversampled fetch then deterministic client-side curation, so filters
  behave identically on old and new indexes.
- Every hit carries `version_status`: `current`, `superseded` (an older
  version than the manifest), `not_yet_effective` (effective date after
  `as_of`/today) or `unknown` (legacy chunk). Superseded and
  not-yet-effective chunks are excluded unless explicitly included.
- `search_for_finding()` builds the query from policy name, missing
  plugins, details and service, plus a category filter inferred from the
  policy name. Remediation grounding uses it.
- `assess_retrieval()` reports sufficiency (hit count, best score, reasons);
  discovery warns per service when evidence is insufficient. Muse Spark
  reasons over the retrieved context; it never replaces retrieval or the
  deterministic control evaluation.

## Prompt safety

Retrieved text is untrusted: `format_excerpts()` renders delimited,
source- and version-tagged evidence blocks, and the audit/remediation
system prompts instruct the model to cite excerpts without following
instructions inside them. Injection resistance is structural (a smuggled
instruction stays visibly inside its quoted block); model compliance is
not asserted offline.

## Evaluation

`backend/eval/retrieval_tasks.json` (10 tasks) with
`backend/eval/run_retrieval_eval.py`:

- `--store fake`: in-memory rank over the real corpus (offline, CI-safe).
- `--store redis`: the production index (ingest first).

Metrics are hit@k and MRR. Current offline result: hit_rate 1.0,
mrr 0.95. `test_retrieval_eval.py` gates on it; update the tasks
alongside any corpus change.

## Verification

- `test_ingestion.py` — headers, derivation, deterministic ids,
  skip/reindex/reset, manifest and embedding record, scoped deletes.
- `test_retrieval.py` — currency matrix, filters, superseded/future
  exclusion, space verification, finding queries, sufficiency,
  excerpt delimiters with an injection payload, prompt grounding lines.
- `test_retrieval_eval.py` — dataset validity plus the relevance gate.
