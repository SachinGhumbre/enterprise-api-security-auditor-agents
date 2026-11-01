# Enterprise API Security Auditor

Ingest your security policies once. Audit your entire API estate anytime, automatically,
against GDPR, HIPAA, PCI-DSS, ISO 27001, OWASP API Top 10, PSD2/SCA, NIST and SOC 2 —
**without anyone on the team needing to know those standards**.

---

## Table of Contents

1. [The problem](#the-problem)
2. [The solution](#the-solution)
3. [Why this matters](#why-this-matters)
4. [Meta models in this project](#meta-models-in-this-project)
5. [Architecture](#architecture)
6. [Repository layout](#repository-layout)
7. [Prerequisites (Windows)](#prerequisites-windows)
8. [Installation (Windows)](#installation-windows)
9. [Configuration](#configuration)
10. [Running the stack](#running-the-stack)
11. [API catalog](#api-catalog)
12. [Postman collection](#postman-collection)
13. [Frontend](#frontend)
14. [Tests](#tests)
15. [Troubleshooting](#troubleshooting)
16. [Technology stack](#technology-stack)
17. [Author](#author)

---

## The problem

**How API security compliance works today — and why it fails.**

Every enterprise has a shelf of security policies: authentication standards, rate-limiting
rules, data-privacy requirements, logging mandates. Every enterprise also has hundreds of
APIs on a gateway. Connecting the two is **entirely manual**:

| Today | Consequence |
|---|---|
| A human reads the policy documents | Takes days; policies are long and change often |
| A human opens each API config and compares it by hand | Error-prone; nobody checks all of them |
| The reviewer must *personally know* GDPR, OWASP, ISO 27001, PCI-DSS… | A scarce, expensive skill — and a single point of failure |
| Findings land in a spreadsheet checklist | Stale the moment a config changes |
| Fixes are figured out from scratch each time | Inconsistent remediation, no standard citations |

**What existed before this project:** manual security reviews, hand-maintained validation
checklists, and tribal knowledge. There was **no agentic system** that could read an
organization's own policies and autonomously judge a live API estate against them.

The result is predictable — security gaps ship to production, audits are reactive, and
compliance depends on whether one expert happened to be in the room.

---

## The solution

**Enterprise API Security Auditor — an agentic AI application.**

Two autonomous agents replace the manual loop end to end:

```
Ingest policies ONCE  →  Audit ANYTIME  →  Get a prioritised fix plan
```

### How it works

1. **Ingest once.** Drop your policy documents into `backend/knowledge_base/`. They are
   chunked, embedded and stored in a Redis vector database. Update them whenever policy
   changes — no code changes, no retraining.
2. **Audit anytime.** The Audit Agent reads your live API Gateway configuration, retrieves the
   policy excerpts relevant to each service (RAG), and uses **Meta's Muse Spark** to
   decide compliance *per policy* — naming exactly which plugins are missing.
3. **Remediate automatically.** The Remediation Agent converts findings into prioritised,
   severity-ranked actions, each citing a real control (OWASP API2:2023, GDPR Art. 32,
   NIST SP 800-53 IA-2…).

### What it replaces

| Before | After |
|---|---|
| Days of manual review | **~57 seconds** for 8 services, 20 policy checks |
| Expert must know every standard | Agent reads your policies; **no standards expertise needed** |
| Static checklist, instantly stale | Re-run on demand; always reflects live config |
| "Something is wrong" | "`jwt` and `oauth2` are missing on `PaymentService`, Critical, ~4h, OWASP API2:2023" |
| Remediation invented each time | Consistent, standard-referenced plan |

### Supported standards

GDPR · HIPAA · PCI-DSS · ISO 27001 · OWASP API Top 10 · PSD2/SCA · PIPEDA · NIST · SOC 2

These aren't hardcoded. The agent evaluates against **whatever policies you ingest**, so
adding a new standard means adding a document — not shipping code.

---

## Why this matters

**Easy to use, but it closes a critical enterprise gap.**

The hard part of API security compliance was never running a scanner — it was **knowing
what to look for**. This project removes that requirement. A developer who has never read
GDPR can run a GDPR audit of their API and get an actionable, cited fix plan in under a
minute.

- **Impact** — turns a multi-day expert task into a one-click operation, and makes
  continuous auditing possible instead of annual
- **Accessible** — ingest policies, press a button; no security certification required
- **Grounded, not guessed** — every verdict reports `policy_sources`, naming the policy
  files that justified it, so findings are auditable rather than opaque
- **Honest** — when a dependency is degraded the API says so explicitly instead of
  silently returning a worse answer

---

## Meta models in this project

This project runs on the **[Meta Model API](https://developer.meta.com/ai/resources/blog/build-with-muse-spark/)**.

| Model | Where it is used |
|---|---|
| **`muse-spark-1.3`** | The reasoning engine for **both** agents — compliance judgement in the Audit Agent and plan generation in the Remediation Agent |
| **Muse Code** | Used as the coding agent while developing this project |
| **Muse Spark Open** | Same lineage; the pipeline can target a self-hosted instance via `META_BASE_URL` |

**Why Muse Spark fits this use case.** Both agents depend on *strict structured
output* — the Audit Agent must return a precise JSON verdict object per service, and the
Remediation Agent a JSON array with ten required fields per item. Muse Spark 1.3 is a
strong instruction-following reasoning model served through an OpenAI-compatible endpoint,
which is exactly the shape this workload needs.

**On model availability.** `GET https://api.meta.ai/v1/models` reports what a key can
use. For this project's key that is `muse-spark-1.3`, `muse-spark-1.3-contributor`,
`muse-spark-1.2(-contributor)`, `muse-spark-1.1`, plus `muse-wonder-1.0`,
`muse-image-1.0`, `muse-voice-transcribe-1.0` and `sam-3.1`.

`muse-spark-open` is **not** served by the Model API - it is an open-weights model
meant to be self-hosted, so requesting `meta-models/muse-spark-open-1026` returns
`model_not_found`. The hackathon brief covers both routes: the Muse Spark series via
Meta Model API (used here), and Muse Spark Open / Muse Glimmer as open weights. Because
Muse Spark Open shares the Muse Spark lineage, this pipeline can be pointed at a
self-hosted instance later by changing `META_BASE_URL` and `META_MODEL` alone.

### How it is wired

Meta Model API exposes an OpenAI-compatible `/chat/completions` surface, so the standard
`openai` SDK is pointed at it:

```python
# backend/common/llm.py
from openai import OpenAI

client = OpenAI(
    base_url="https://api.meta.ai/v1",     # META_BASE_URL
    api_key=config.META_API_KEY,           # META_API_KEY
)

response = client.chat.completions.create(
    model="muse-spark-1.3",   # META_MODEL
    messages=messages,
    max_tokens=config.LLM_MAX_TOKENS,
)
```

All LLM access funnels through `backend/common/llm.py`, so the provider is a single
configuration switch (`meta` | `kong`) rather than something scattered across
the agents.

### Setup — one value to change

```ini
# backend/.env
META_API_KEY = <paste the key from the Meta Model API console>
META_MODEL   = muse-spark-1.3
META_BASE_URL = https://api.meta.ai/v1
LLM_PROVIDER = meta
```

Then verify in one command:

```powershell
python backend\scripts\verify_meta.py
```

It checks configuration, network reachability, a live chat completion, and a real
structured-audit response — and tells you precisely which step failed.

> **Note on embeddings.** Meta Model API does not currently expose an embeddings
> endpoint, so the RAG *retrieval* layer uses a separate embedding provider
> (`EMBEDDING_PROVIDER`). All **reasoning** — every compliance verdict and every
> remediation action — runs on Muse Spark.

---

## Architecture

### System containers

```mermaid
---
title: System containers — Enterprise API Security Auditor
---
flowchart TB
    USER["Security Auditor"]

    subgraph CLIENT["Client tier"]
        PORTAL["Auditor Portal<br/>React 19 SPA · :3000"]
    end

    subgraph SERVICES["Application tier · Flask"]
        AGENTS["AI Agents API · :5000<br/>Audit Agent · Remediation Agent<br/>LangGraph orchestration"]
        RAG["Knowledge Service · :5001<br/>Corpus ingest · KNN retrieval"]
        HARNESS["Redis Harness · :5002<br/>Index diagnostics"]
    end

    subgraph EXTERNAL["Data and external systems"]
        REDIS[("Redis Stack<br/>RediSearch vector index")]
        KONG["Kong Konnect<br/>Services · Routes · Plugins"]
        META["Meta Model API<br/>muse-spark-1.3 · reasoning"]
    end

    FALLBACK[("Cached inventory<br/>filtered_kong_data.json<br/>offline fallback")]
    KONGAI["Kong AI Gateway<br/>Optional LLM route"]

    USER --> PORTAL
    PORTAL --> AGENTS
    PORTAL --> RAG
    PORTAL --> HARNESS
    AGENTS --> REDIS
    AGENTS --> KONG
    AGENTS --> META
    AGENTS -. fallback .-> FALLBACK
    AGENTS -. optional .-> KONGAI
    RAG --> REDIS
    HARNESS --> REDIS

    classDef user fill:#EAF1FB,stroke:#1F3A5F,stroke-width:2px,color:#111;
    classDef client fill:#EAF1FB,stroke:#1F3A5F,stroke-width:1.5px,color:#111;
    classDef svc fill:#E9F3F2,stroke:#0E7C7B,stroke-width:1.5px,color:#111;
    classDef ext fill:#F4F1E8,stroke:#8A6D1B,stroke-width:1.5px,color:#111;
    classDef opt fill:#FFFFFF,stroke:#6B7280,stroke-width:1.5px,stroke-dasharray:6 3,color:#111;
    class USER user;
    class PORTAL client;
    class AGENTS,RAG,HARNESS svc;
    class REDIS,KONG,META ext;
    class FALLBACK,KONGAI opt;
    style CLIENT fill:#F7FAFD,stroke:#9DB4CC
    style SERVICES fill:#F5FAF9,stroke:#8FC2BE
    style EXTERNAL fill:#FCFAF4,stroke:#C9B87A
```


### Ingest and audit sequences

Ingestion and auditing are separate flows — ingest the corpus once, audit the estate anytime.

```mermaid
---
title: Ingest policies (once)
---
sequenceDiagram
    autonumber
    actor Auditor
    participant Portal as Portal
    participant Know as Knowledge Service (5001)
    participant Embed as Embedding Provider
    participant Redis as Redis Stack

    Auditor->>Portal: Upload or update policy documents
    Portal->>Know: POST /api/v1/knowledge/ingest
    Know->>Know: Chunk corpus (900 chars, 120 overlap)
    Know->>Embed: Embed chunks
    Embed-->>Know: Vectors (1536-dim)
    Know->>Redis: Upsert vectors and metadata
    Redis-->>Know: ACK
    Know-->>Portal: Ingest summary (chunks, index)
    Portal-->>Auditor: Corpus ready
```

```mermaid
---
title: Audit estate (anytime)
---
sequenceDiagram
    autonumber
    actor Auditor
    participant Portal as Portal
    participant Agents as AI Agents API (5000)
    participant Kong as Kong Konnect
    participant Redis as Redis Stack
    participant Meta as Meta Model API

    Auditor->>Portal: Start audit (standards, services)
    Portal->>Agents: POST /api/v1/ai-agents/audit

    rect rgb(240,244,248)
    Note over Agents,Kong: Perceive - read live estate
    Agents->>Kong: List services, routes, plugins
    Kong-->>Agents: Inventory (or cached fallback)
    end

    rect rgb(233,243,242)
    Note over Agents,Redis: Retrieve - ground in policy
    Agents->>Redis: KNN top-k chunks per service
    Redis-->>Agents: Policy excerpts and sources
    end

    rect rgb(244,241,232)
    Note over Agents,Meta: Reason - judge compliance
    Agents->>Meta: Verdict prompt and context (1 call per service)
    Meta-->>Agents: Compliance verdicts
    end

    Agents->>Agents: Score, summarise, persist report
    Agents-->>Portal: Audit report and summary
    Portal-->>Auditor: Findings dashboard
    Auditor->>Portal: Generate remediation plan
    Portal->>Agents: POST /api/v1/ai-agents/remediate
    Agents->>Meta: Batched findings (5 per batch)
    Meta-->>Agents: Prioritised actions
    Agents-->>Portal: Remediation plan
```

### Runtime topology

```mermaid
---
title: Runtime topology — services, ports, and dependencies
---
flowchart TB
    subgraph UI["React Dashboard :3000"]
        D[Overview / Knowledge / Audit / Remediation]
    end

    subgraph SVC["Backend services"]
        A["AI Agents API :5000<br/>agents/init_auditor.py"]
        K["Knowledge Service :5001<br/>rag/knowledge_ingestor.py"]
        R["Redis Harness :5002<br/>redis-test.py"]
    end

    subgraph DATA["Data & models"]
        RS[("Redis Stack<br/>RediSearch vector index")]
        KONG["Kong Konnect<br/>services / routes / plugins"]
        META["Meta Model API<br/>muse-spark-1.3"]
    end

    D -->|audit, remediate| A
    D -->|ingest, search| K
    D -->|health| R
    K -->|embed + store| RS
    A -->|KNN retrieve| RS
    A -->|read config| KONG
    A -->|reason / judge| META
    R --> RS

    classDef client fill:#EAF1FB,stroke:#1F3A5F,stroke-width:1.5px,color:#111;
    classDef svc fill:#E9F3F2,stroke:#0E7C7B,stroke-width:1.5px,color:#111;
    classDef ext fill:#F4F1E8,stroke:#8A6D1B,stroke-width:1.5px,color:#111;
    class D client;
    class A,K,R svc;
    class RS,KONG,META ext;
    style UI fill:#F7FAFD,stroke:#9DB4CC
    style SVC fill:#F5FAF9,stroke:#8FC2BE
    style DATA fill:#FCFAF4,stroke:#C9B87A
```

### Agent pipeline

```mermaid
---
title: Agent pipeline — Perceive to Act
---
flowchart LR
    P[Perceive<br/>Kong config] --> RE[Retrieve<br/>policy chunks via KNN]
    RE --> RA["Reason<br/>Muse Spark verdict"]
    RA --> PL[Plan<br/>score & summarise]
    PL --> AC[Act<br/>persist artifact]
    AC --> E([END])

    classDef step fill:#E9F3F2,stroke:#0E7C7B,stroke-width:1.5px,color:#111;
    classDef done fill:#1F3A5F,stroke:#1F3A5F,stroke-width:1.5px,color:#fff;
    class P,RE,RA,PL,AC step;
    class E done;
```

Both agents follow this **Perceive → Retrieve → Reason → Plan → Act** loop.

The **Retrieve** stage is what makes this RAG rather than a bare prompt: each service's
plugin set becomes a query, the top-k matching policy excerpts are pulled from Redis, and
only those excerpts are given to the model. Every verdict reports a `policy_sources`
array naming the files that grounded it.

---

## Repository layout

```
enterprise-api-security-auditor-agents/
├── enterprise-api-security-auditor-agents.postman_collection.json   # 24 requests, 6 folders
├── README.md
├── redis-test.py                        # :5002  standalone Redis harness
├── backend/
│   ├── .env                             # all configuration lives here
│   ├── requirements.txt
│   ├── docker-compose.yaml              # Redis Stack
│   ├── common/                          # shared layer
│   │   ├── config.py                    #   env loading + effective config
│   │   ├── embeddings.py                #   local embedding providers
│   │   ├── llm.py                       #   Meta | Kong AI Gateway
│   │   └── vector_store.py              #   Redis index, upsert, KNN search
│   ├── scripts/verify_meta.py           #   one-command Meta Model API check
│   ├── rag/knowledge_ingestor.py        # :5001  ingest + retrieval API
│   ├── agents/
│   │   ├── auditor_agent.py             #   LangGraph node + graph definitions
│   │   ├── init_auditor.py              # :5000  agent HTTP API
│   │   └── filtered_kong_data.json      #   cached inventory (offline fallback)
│   ├── knowledge_base/                  # the policy corpus that gets ingested
│   ├── kong_config/                     # Kong Konnect declarative config
│   ├── artifacts/                       # generated reports (gitignored)
│   └── tests/                           # pytest suite, fully offline
└── frontend/                            # :3000  React + Tailwind dashboard
    └── src/
        ├── api/client.js                #   every backend call goes through here
        ├── components/                  #   Header, Sidebar, Login, ui primitives
        └── pages/                       #   Overview, KnowledgeBase, Audit, Remediation
```

---

## Prerequisites (Windows)

| Requirement | Version | Notes |
|---|---|---|
| **Python** | 3.11+ | Tested on 3.14. `py --version` |
| **Node.js** | 18+ | `node --version` |
| **Docker Desktop** | latest | Only if running Redis locally |
| **Redis Stack** | 7+ | **Must include the RediSearch module** |
| **Meta Model API key** | — | **Required.** From the Meta Model API console |
| **Azure OpenAI** | — | Optional fallback provider, and embeddings for RAG |
| **Kong Konnect** _or_ **Kong Gateway** | — / 3.x | Optional — the audit falls back to a cached inventory |

> **Plain `redis` will not work.** Vector search needs the RediSearch module, which
> ships in `redis/redis-stack-server`. Verify with `GET /api/v1/knowledge/health` — it
> reports `search_module: true` when correct.

---

## Installation (Windows)

All commands are PowerShell, run from the repository root.

### 1. Clone and enter the project

```powershell
cd C:\Users\<you>\projects
git clone <repo-url> enterprise-api-security-auditor-agents
cd enterprise-api-security-auditor-agents
```

### 2. Start Redis Stack

**Option A — Docker (recommended)**

```powershell
docker compose -f backend\docker-compose.yaml up -d
docker ps   # confirm the `redis` container is running
```

**Option B — remote/managed Redis**
Skip Docker and point `REDIS_HOST` / `REDIS_PORT` in `backend\.env` at your instance.

Verify the module is present:

```powershell
docker exec -it redis redis-cli MODULE LIST
# expect an entry with name "search"
```

### 3. Create the Python virtual environment

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

> If PowerShell blocks activation:
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

### 4. Configure `backend\.env`

See [Configuration](#configuration) below. At minimum set **`META_API_KEY`** and
`REDIS_HOST`. Then confirm with `python backend\scripts\verify_meta.py`.

### 5. Install frontend dependencies

```powershell
cd frontend
npm install
cd ..
```

---

## Configuration

Everything is read from **`backend\.env`**. It is loaded by absolute path, so services
work no matter which directory you launch them from.

### Redis

| Variable | Default | Purpose |
|---|---|---|
| `REDIS_HOST` | `localhost` | Redis Stack hostname |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PASSWORD` | _(none)_ | Optional auth |
| `INDEX_NAME` | `security_auditor_index` | RediSearch index name |
| `KEY_PREFIX` | `embedding:` | Key prefix the index covers |
| `VECTOR_DIMENSIONS` | `1536` | **Must match the embedding model** |

### Knowledge base

| Variable | Default | Purpose |
|---|---|---|
| `KNOWLEDGE_BASE_DIR` | `knowledge_base` | Policy corpus, relative to `backend/` |
| `CHUNK_SIZE` | `900` | Characters per chunk |
| `CHUNK_OVERLAP` | `120` | Overlap between chunks |

### Meta Model API (primary LLM)

| Variable | Default | Purpose |
|---|---|---|
| `META_API_KEY` | _(none)_ | **Required.** Key from the Meta Model API console |
| `META_MODEL` | `muse-spark-1.3` | Latest Muse Spark on the Model API |
| `META_BASE_URL` | `https://api.meta.ai/v1` | OpenAI-compatible endpoint |

Verify with `python backend\scripts\verify_meta.py`.


### Provider selection

| Variable | Values | Behaviour |
|---|---|---|
| `LLM_PROVIDER` | `meta` \| `kong` \| `azure` \| `auto` | `meta` is the hackathon target; `auto` prefers Meta when `META_API_KEY` is set, then Kong, then Azure |
| `EMBEDDING_PROVIDER` | `auto` \| `azure` \| `local` | `local` is a deterministic hashed bag-of-words vector — lexical match only, see the warning below |

> **About `EMBEDDING_PROVIDER=local`.** It needs local embeddings deployment, so the
> RAG pipeline runs offline. But it is a **lexical** embedding: it matches shared
> vocabulary, *not* paraphrase. Keyword queries rank correctly; semantically-worded
> questions will not. Deploy `text-embedding-3-small` in Azure and set
> `EMBEDDING_PROVIDER=azure` for real semantic retrieval if needed.

### Kong

Both **Kong Konnect** (SaaS control plane) and a **self-managed Admin API** are
supported. They differ in three ways, all handled automatically:

| | Kong Konnect | Self-managed |
|---|---|---|
| Auth header | `Authorization: Bearer kpat_...` | `kong-admin-token: <token>` |
| Entity path | `/core-entities/services` | `/services` |
| TLS | valid public cert → verify **on** | usually self-signed → verify **off** |

Sending a Konnect PAT as `kong-admin-token` returns **401**; requesting a bare
`/services` on a control plane returns **404**.

| Variable | Purpose |
|---|---|
| `KONG_ADMIN_API` | Admin API base URL (trailing slash stripped automatically) |
| `KONG_ADMIN_TOKEN` | Konnect PAT (`kpat_...`) or self-managed admin token |
| `KONG_ADMIN_MODE` | `auto` \| `konnect` \| `onprem` — `auto` detects Konnect from the hostname |
| `KONG_ADMIN_VERIFY_SSL` | Defaults to `true` for Konnect, `false` for self-managed |
| `KONG_PAGE_SIZE` | Page size when listing entities (default `1000`) |
| `KONG_HTTP_TIMEOUT` | Per-request timeout in seconds (default `30`) |
| `KONG_AI_PROXY_HOSTNAME` | Optional — Kong AI Gateway base URL |
| `KONG_API_KEY` | Optional — `x-api-key` for the AI Gateway |

**Konnect setup**

1. In Konnect, go to **Personal Access Tokens** and create a PAT (`kpat_...`).
2. Copy the **control plane ID** from the control-plane URL.
3. Set, using your geo (`eu`, `us`, `au`, `in`, `me`):

```ini
KONG_ADMIN_API = https://eu.api.konghq.com/v2/control-planes/<control-plane-id>
KONG_ADMIN_TOKEN = kpat_xxxxxxxx
KONG_ADMIN_MODE = auto
```

Confirm with `GET /api/v1/ai-agents/health` → `dependencies.kong_mode: "konnect"`
and a non-zero `dependencies.kong_services`.

> **Effective plugin set.** The inventory fetches services, routes and plugins
> once each and joins them in memory — 3 requests regardless of estate size,
> rather than `1 + 2N`. `service_plugins` combines plugins bound to the service,
> plugins bound to **any of its routes**, and gateway-wide plugins. Most Konnect
> estates bind plugins at the route level, so without the route rollup nearly
> every service would look unprotected.

### TLS behind a corporate proxy

Corporate TLS-inspection proxies re-sign traffic with an internal root CA that
Windows trusts but `certifi` (which `requests` uses) does not. The symptom is an
`SSLError` from the app against a URL that `curl` reaches fine.

`backend/requirements.txt` includes **`truststore`**, which makes Python use the
OS certificate store, so verification stays **enabled**. Check it is active:

```
GET /api/v1/ai-agents/health  →  config.tls.system_trust_store: true
```

Last resort only: `KONG_ADMIN_VERIFY_SSL = false`.

### LLM limits

| Variable | Default | Purpose |
|---|---|---|
| `LLM_MAX_TOKENS` | `8000` | Output cap per call. Reasoning models count reasoning tokens against this. |
| `REMEDIATION_BATCH_SIZE` | `5` | Findings per remediation call |

> Remediation is **batched** on purpose. One call for all findings grows with the
> estate and silently truncates once the response passes the cap — yielding
> invalid JSON and losing the entire plan. With 16 findings the response landed at
> ~3,900–4,100 tokens against the old 4,000 cap, so it parsed intermittently.
> Batching bounds every response; a batch that still fails is retried one finding
> at a time so a single bad response cannot discard the group.

### Ports

| Variable | Default | Service |
|---|---|---|
| `AGENTS_PORT` | `5000` | AI Agents API |
| `KNOWLEDGE_PORT` | `5001` | Knowledge Ingestor |
| `REDIS_TEST_PORT` | `5002` | Redis harness |

---

## Running the stack

Run each service in its **own** PowerShell window, with the venv activated.

```powershell
# Terminal 1 - Redis Test Harness  (:5002)
backend\.venv\Scripts\Activate.ps1
python redis-test.py

# Terminal 2 - Knowledge Ingestor  (:5001)
backend\.venv\Scripts\Activate.ps1
python backend\rag\knowledge_ingestor.py

# Terminal 3 - AI Agents API  (:5000)
backend\.venv\Scripts\Activate.ps1
python backend\agents\init_auditor.py

# Terminal 4 - React dashboard  (:3000)
cd frontend
npm start
```

Each service prints its effective configuration on startup.

### First-run order

```powershell
# 1. Confirm everything is wired up
curl http://localhost:5001/api/v1/knowledge/health
curl http://localhost:5000/api/v1/ai-agents/health

# 2. Ingest the policy corpus into Redis
curl -X POST http://localhost:5001/api/v1/knowledge/ingest `
     -H "Content-Type: application/json" -d '{\"reset\": true}'

# 3. Prove retrieval works
curl -X POST http://localhost:5001/api/v1/knowledge/search `
     -H "Content-Type: application/json" `
     -d '{\"query\": \"Which plugin enforces authentication?\", \"top_k\": 3}'

# 4. Run the audit, then remediation
curl -X POST http://localhost:5000/api/v1/ai-agents/audit `
     -H "Content-Type: application/json" `
     -d '{\"selected_standards\": [\"OWASP API Top 10\", \"GDPR\"]}'

curl -X POST http://localhost:5000/api/v1/ai-agents/remediate `
     -H "Content-Type: application/json" -d '{}'
```

> PowerShell's `curl` is an alias for `Invoke-WebRequest` and quotes JSON differently.
> For anything non-trivial, use the Postman collection or `curl.exe` explicitly.

---

## API catalog

### AI Agents — `http://localhost:5000`

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/ai-agents/health` | LLM provider, Redis state, policy chunk count, Kong reachability |
| `GET` | `/api/v1/ai-agents/models` | Model ids the key can use; resolves `model_not_found` |
| `GET` | `/api/v1/ai-agents/kong/services` | Inventory to be audited, with `source` provenance |
| `POST` | `/api/v1/ai-agents/audit` | Run the Audit Agent |
| `POST` | `/api/v1/ai-agents/remediate` | Run the Remediation Agent |
| `GET` | `/api/v1/ai-agents/audit/report` | Replay the last audit report |
| `GET` | `/api/v1/ai-agents/remediate/plan` | Replay the last remediation plan |

<details>
<summary><strong>POST /api/v1/ai-agents/audit</strong></summary>

**Request** — every field optional:
```json
{
  "selected_standards": ["OWASP API Top 10", "GDPR", "NIST"],
  "service_names": ["Healthcheck", "orders-api"],
  "top_k": 4,
  "kong_data": [
    { "service_name": "PaymentService", "service_id": "x", "service_plugins": ["key-auth"] }
  ]
}
```
- `service_names` — audit only these services (case-insensitive). Cost is one LLM call
  per service, so this is the fast path while iterating.
- `kong_data` — bypasses the Kong Admin API entirely; useful for demos and for testing
  specific plugin combinations.

**Response**
```json
{
  "audit_report": {
    "HealthService:policy:HealthService": {
      "serviceName": "HealthService",
      "service_plugins": ["key-auth", "request-transformer"],
      "policy_sources": ["01_authentication_policy.txt"],
      "policies": [
        {
          "policy_name": "Authentication Policy v1.0",
          "comply": false,
          "missing_plugins": ["jwt", "oauth2"],
          "details": "..."
        }
      ]
    }
  },
  "summary": {
    "services_audited": 2, "policies_evaluated": 3,
    "compliant": 1, "non_compliant": 2, "compliance_rate": 33.3,
    "retrieved_policy_chunks": 8, "llm_provider": "local"
  },
  "kong_source": "kong_konnect",
  "warnings": []
}
```
Takes ~30–60s: one LLM call per service. Measured against a Konnect control plane
with 8 services: **57s**, 20 policies evaluated. `kong_source` is one of
`kong_konnect`, `kong_onprem`, `request` or `cached_file`.
</details>

<details>
<summary><strong>POST /api/v1/ai-agents/remediate</strong></summary>

**Request** — `{}` falls back to the last saved audit report:
```json
{ "audit_report": { "...": "output of the audit endpoint" } }
```

**Response** — a severity-sorted array (Critical first):
```json
[
  {
    "serviceName": "HealthService",
    "policyName": "Authentication Policy v1.0",
    "issue": "...",
    "missingPlugin": "jwt, oauth2",
    "recommendedAction": "...",
    "severity": "Critical",
    "owner": "API Gateway Team",
    "estimatedEffort": "4 hours",
    "impact": "...",
    "securityStandardReference": "OWASP API2:2023 Broken Authentication"
  }
]
```
Add `?envelope=true` to get `{remediation_plan, summary, findings_count, note, error}`
instead of the bare array.
</details>

### Knowledge Ingestor / RAG — `http://localhost:5001`

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/knowledge/health` | Embedding config, Redis + RediSearch, corpus directory |
| `POST` | `/api/v1/knowledge/index` | Create the vector index (`{"recreate": true}` to rebuild) |
| `POST` | `/api/v1/knowledge/ingest` | Chunk, embed and store the corpus (`{"reset": true}`) |
| `POST` | `/api/v1/knowledge/search` | **KNN retrieval** — `{"query": "...", "top_k": 5}` |
| `GET` | `/api/v1/knowledge/get_all_embeddings` | Inventory — `?limit=50&include_vector=false` |
| `GET` | `/api/v1/knowledge/stats` | Index name, doc count, dimensions, module presence |
| `DELETE` | `/api/v1/knowledge/embeddings` | Clear the corpus (index definition is kept) |

<details>
<summary><strong>POST /api/v1/knowledge/search</strong> — the request that proves RAG</summary>

```json
{ "query": "Which plugin enforces authentication on a Kong service?", "top_k": 3 }
```
```json
{
  "query": "...", "count": 3, "embedding_provider": "local",
  "results": [
    {
      "id": "embedding:331739f3-...",
      "source": "01_authentication_policy.txt",
      "score": 0.2343,
      "content": "Policy Name: Authentication Policy v1.0 ...",
      "metadata": { "chunk_index": 0, "chunk_count": 1 }
    }
  ]
}
```
`score` is cosine **similarity** (higher is better), converted from RediSearch's distance.
</details>

### Redis Test Harness — `http://localhost:5002`

| Method | Path | Description |
|---|---|---|
| `GET` | `/redis/index_info` | Host, port, loaded `.env`, index presence, doc count |
| `POST` | `/redis/create_index` | Create index — `index_name`, `prefix`, `vector_dimensions`, `recreate` |
| `POST` | `/redis/add_embedding` | Store a text/JSON pair (connectivity check, **not** a real vector) |
| `GET` | `/redis/all_embeddings` | List every `embedding:*` key — `?limit=10&include_vector=false` |
| `DELETE` | `/redis/all_embeddings` | Delete every `embedding:*` key |

> `add_embedding` writes a JSON blob, not a FLOAT32 vector, so documents created there are
> **not** returned by KNN search, yet they still count toward `num_docs`. Use the
> ingestion API for real vectors. In the listing, `vector_dimensions: 0` marks a
> document that has no usable vector.

---

## Postman collection

Import **`enterprise-api-security-auditor-agents.postman_collection.json`** from the repo root
— 24 requests across 6 folders.

| Folder | Contents |
|---|---|
| `00 - Health Checks` | All three services |
| `01 - Redis Test Harness (5002)` | Index + embedding CRUD |
| `02 - Knowledge Ingestion / RAG (5001)` | Create index → ingest → search → stats |
| `03 - AI Agent: Audit (5000)` | Inventory, audit (live / offline / scoped), replay |
| `04 - AI Agent: Remediate (5000)` | Plan generation and replay |
| `05 - Meta Model API (direct)` | List models, chat completion, structured audit prompt — direct probes, no backend |

Collection variables (`agents_url`, `knowledge_url`, `redis_test_url`) default to
localhost. **Run Security Audit** stores its report in the `audit_report` variable, so
**Generate Remediation Plan** works with no copy/paste.

---

## Frontend

```powershell
cd frontend
npm install
npm start          # http://localhost:3000
npm run build      # production bundle
```

Demo credentials: **`ai_champion` / `Meta@123`** (presentation scaffolding — there is
no backend auth).

| Page | What it does |
|---|---|
| **Overview** | Live health of all three services, agent pipeline, quick-start actions |
| **Knowledge Base** | Ingest the corpus, run vector searches, browse stored chunks |
| **Security Audit** | Pick standards, view Kong inventory, run the audit, export JSON |
| **Remediation** | Generate the prioritised plan, severity breakdown, export JSON |

Endpoints default to localhost and can optionally be overridden in **`frontend\.env`**:

```
REACT_APP_AGENTS_URL=http://localhost:5000
REACT_APP_KNOWLEDGE_URL=http://localhost:5001
REACT_APP_REDIS_TEST_URL=http://localhost:5002
```

---

## Tests

```powershell
backend\.venv\Scripts\Activate.ps1
python -m pytest backend\tests -q
```

54 tests covering every agent node, both compiled graphs, Konnect vs self-managed auth
and entity paths, pagination, the route-plugin rollup, remediation batching and its
per-finding retry, severity mapping, JSON-parsing failure paths, the Kong fallback, and
the **Meta Model API provider** (resolution, model id, parameter fallbacks, fenced-JSON
parsing, and a full audit-graph run on Meta). The LLM, Kong and Redis are all stubbed, so the
suite runs offline with no credentials.

---

## Troubleshooting

| Symptom | Cause & fix |
|---|---|
| `model_not_found` from Meta | The key is valid and the request reached Meta - only `META_MODEL` is wrong. Run `GET /api/v1/ai-agents/models` (or `curl -H 'Authorization: Bearer <KEY>' https://api.meta.ai/v1/models`) and set `META_MODEL` to a listed id. Note `muse-spark-open` is open-weights only, not on the API. |
| `META_API_KEY is not set` | Paste the key into `backend/.env` and restart. Run `python backend\scripts\verify_meta.py`. |
| HTTP 403 with an HTML body from `api.meta.ai` | A corporate proxy (Zscaler etc.) is blocking Meta, not an auth failure. Allowlist `api.meta.ai` / `dev.meta.ai` or run off the corporate network. |
| `401` from Meta Model API | Key invalid or expired. Re-issue it in the Meta Model API console. |
| Meta model name rejected | Confirm `META_MODEL=muse-spark-1.3`. |
| `404 DeploymentNotFound` | The name is set but no such deployment exists on that endpoint. List them: `GET {endpoint}/openai/deployments?api-version=2023-03-15-preview` with header `api-key`. |
| `400 OperationNotSupported` | You pointed the embedding variable at a **chat** deployment. They are separate resources. |
| `search_module: false` in health | Running plain `redis`. Switch to `redis/redis-stack-server`. |
| `Index ... does not exist` on search | Run `POST /api/v1/knowledge/ingest` first. |
| Embedding dimension mismatch | `VECTOR_DIMENSIONS` must match the model: `3-small`=1536, `3-large`=3072. Then `POST /api/v1/knowledge/index` with `{"recreate": true}`. |
| Kong `401 Unauthorized` | A Konnect PAT was sent as `kong-admin-token`. Set `KONG_ADMIN_MODE=konnect` (or leave `auto`) so it goes out as `Authorization: Bearer`. |
| Kong `404 Not Found` on `/services` | Konnect nests entities under `core-entities/`, and `KONG_ADMIN_API` must include `/v2/control-planes/<id>`. |
| `'utf-8' codec can't decode byte 0xNN` on `/redis/all_embeddings` | The connection was decoding every field as text, but ingested chunks store `vector` as packed FLOAT32 bytes. Fixed by using `decode_responses=False` and decoding per field; if you see it elsewhere, do the same rather than skipping the field. |
| `num_docs` higher than the ingested chunk count | Leftover `add_embedding` test documents. Remove them, or `DELETE /api/v1/knowledge/embeddings` then re-ingest. |
| `SSLError` from the app but `curl` works | Corporate TLS-inspection proxy. `pip install truststore` (already in requirements) to use the OS trust store. Verify via `config.tls.system_trust_store` in health. |
| Remediation returns `Model did not return a parsable JSON array` | Response exceeded the token cap mid-JSON. Lower `REMEDIATION_BATCH_SIZE` or raise `LLM_MAX_TOKENS`. |
| Services show no plugins but Kong has them | Plugins are bound at route level. The inventory rolls route plugins up to their service — confirm via `GET /api/v1/ai-agents/kong/services`. |
| Audit returns `kong_source: cached_file` | Kong Admin API unreachable; the agent used `agents/filtered_kong_data.json`. The `warnings` array explains why. |
| `Cannot find module 'tailwind-scrollbar'` | `cd frontend && npm install`. The plugin now loads optionally, so this should no longer break the build. |
| Two servers on one port (Windows) | Windows permits duplicate binds and the **older** process wins, so you can serve stale code. Check with `Get-NetTCPConnection -LocalPort 5001 -State Listen`, then `Stop-Process -Id <pid> -Force`. |
| Changes not taking effect | A `debug=True` Flask reloader may still be holding the port. Stop every `python.exe` and restart. |

---

## Technology stack

- **Models** — **Meta Model API** (`muse-spark-1.3`, Muse Spark series) · **Muse Code** (development)
- **Backend** — Python 3.11+ · Flask · LangGraph · Redis Stack (RediSearch) · NumPy
- **Frontend** — React 19 · Tailwind CSS 3 · lucide-react · Create React App
- **Gateway** — Kong API Gateway 3.x · Kong AI Gateway (AI Proxy, RAG Injector, Prompt Guard, Response Transformer)
- **Tooling** — Postman · pytest · Docker Compose

---

## Author

**Sachin Ghumbre** — Enterprise API Security Auditor
License: Proprietary
