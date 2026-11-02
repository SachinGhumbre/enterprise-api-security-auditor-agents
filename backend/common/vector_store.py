"""
===============================================================================
 File Name   : common/vector_store.py
 Description : Redis Stack vector index helpers - create, upsert, list, delete
               and KNN search over security policy chunks.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import json
import uuid

import numpy as np
import redis
from redis.commands.search.field import TagField, TextField, VectorField
from redis.commands.search.index_definition import IndexDefinition, IndexType
from redis.commands.search.query import Query

from . import config, embeddings

_client = None


def get_client():
    """Shared connection. decode_responses=False because vectors are raw bytes."""
    global _client
    if _client is None:
        _client = redis.Redis(
            host=config.REDIS_HOST,
            port=config.REDIS_PORT,
            username=config.REDIS_USERNAME,
            password=config.REDIS_PASSWORD,
            decode_responses=False,
            socket_connect_timeout=10,
            socket_timeout=30,
        )
    return _client


def ping():
    try:
        return bool(get_client().ping())
    except Exception:
        return False


def has_search_module():
    """RediSearch is required; plain redis:alpine will not work."""
    try:
        names = {(m.get("name") or m.get(b"name", b"")) for m in get_client().module_list()}
        names = {n.decode() if isinstance(n, bytes) else n for n in names}
        return "search" in {n.lower() for n in names}
    except Exception:
        return False


def index_exists(index_name=None):
    try:
        get_client().ft(index_name or config.INDEX_NAME).info()
        return True
    except Exception:
        return False


def build_schema(dimensions=None):
    dimensions = dimensions or config.VECTOR_DIMENSIONS
    return (
        TextField("content"),
        TextField("text"),
        TextField("source"),
        VectorField("vector", "FLAT", {
            "TYPE": "FLOAT32",
            "DIM": dimensions,
            "DISTANCE_METRIC": "COSINE",
        }),
        TagField("metadata"),
    )


def create_index(index_name=None, prefix=None, dimensions=None, recreate=False):
    """Create the vector index. Returns (created: bool, detail: dict)."""
    index_name = index_name or config.INDEX_NAME
    prefix = prefix or config.KEY_PREFIX
    dimensions = dimensions or config.VECTOR_DIMENSIONS
    client = get_client()

    if index_exists(index_name):
        if not recreate:
            return False, {"index_name": index_name, "message": "Index already exists."}
        client.ft(index_name).dropindex(delete_documents=False)

    definition = IndexDefinition(prefix=[prefix], index_type=IndexType.HASH)
    client.ft(index_name).create_index(build_schema(dimensions), definition=definition)
    return True, {
        "index_name": index_name,
        "prefix": prefix,
        "vector_dimensions": dimensions,
        "recreated": recreate,
    }


def ensure_index():
    """Create the index if missing, and rebuild it if its dimensions no longer
    match VECTOR_DIMENSIONS (otherwise every later KNN query fails)."""
    if not index_exists():
        return create_index()[0]

    try:
        info = get_client().ft(config.INDEX_NAME).info()
        for attr in info.get("attributes", []):
            flat = [a.decode() if isinstance(a, bytes) else str(a) for a in attr]
            if "vector" in flat and "dim" in [f.lower() for f in flat]:
                dim = int(flat[[f.lower() for f in flat].index("dim") + 1])
                if dim != config.VECTOR_DIMENSIONS:
                    create_index(recreate=True)
                    return True
    except Exception:
        pass
    return False


def upsert_chunk(content, metadata, embedding, chunk_id=None, source=""):
    chunk_id = chunk_id or str(uuid.uuid4())
    key = f"{config.KEY_PREFIX}{chunk_id}"
    get_client().hset(key, mapping={
        "content": content,
        "text": content,
        "source": source,
        "vector": embeddings.to_bytes(embedding),
        "metadata": json.dumps(metadata),
    })
    return chunk_id, key


def _decode(value):
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value


def _parse_metadata(raw):
    raw = _decode(raw)
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return {"raw": raw}


def iter_keys():
    return get_client().scan_iter(match=f"{config.KEY_PREFIX}*", count=500)


def list_chunks(limit=None, include_vector=False):
    """List stored chunks via SCAN so it works even without an index.

    FT.SEARCH would cap at 10 results by default and requires the index to
    exist, which makes it a poor fit for an inventory endpoint.
    """
    client = get_client()
    out = []
    for key in iter_keys():
        if limit is not None and len(out) >= limit:
            break
        data = client.hgetall(key)
        if not data:
            continue
        item = {
            "id": _decode(key),
            "content": _decode(data.get(b"content", b"")),
            "source": _decode(data.get(b"source", b"")),
            "metadata": _parse_metadata(data.get(b"metadata")),
        }
        if include_vector:
            item["vector"] = embeddings.from_bytes(data.get(b"vector", b""))
        else:
            item["vector_dimensions"] = len(data.get(b"vector", b"")) // 4
        out.append(item)
    return out


def count_chunks():
    return sum(1 for _ in iter_keys())


def delete_all():
    client = get_client()
    deleted = []
    for key in iter_keys():
        client.delete(key)
        deleted.append(_decode(key))
    return deleted


def search(query_text, top_k=5, filters=None):
    """Cosine KNN search. Returns chunks ordered most-similar first.

    `filters` narrows by chunk metadata (category, policy_version,
    applies_to, effective_as_of) and drops superseded / not-yet-effective
    chunks unless explicitly included. Every hit carries version_status.
    """
    ensure_index()
    require_embedding_space()
    vector = embeddings.embed(query_text)
    fetch_k = int(top_k) * (FILTER_OVERSAMPLE if filters else 1)

    query = (
        Query(f"*=>[KNN {fetch_k} @vector $vec AS score]")
        .sort_by("score")
        .return_fields("content", "source", "metadata", "score")
        .dialect(2)
    )
    result = get_client().ft(config.INDEX_NAME).search(
        query, query_params={"vec": np.asarray(vector, dtype=np.float32).tobytes()}
    )

    hits = []
    for doc in result.docs:
        distance = float(getattr(doc, "score", 1.0))
        hits.append({
            "id": _decode(doc.id),
            "content": _decode(getattr(doc, "content", "")),
            "source": _decode(getattr(doc, "source", "")),
            "metadata": _parse_metadata(getattr(doc, "metadata", "")),
            # COSINE distance -> similarity, easier to read in a UI
            "score": round(1.0 - distance, 4),
        })
    hits = apply_filters(hits, filters)
    return hits[:int(top_k)]


def stats():
    info = {}
    if index_exists():
        try:
            raw = get_client().ft(config.INDEX_NAME).info()
            info = {
                "num_docs": int(raw.get("num_docs", 0) or 0),
                "indexing": raw.get("indexing"),
            }
        except Exception:
            info = {}
    return {
        "redis_host": config.REDIS_HOST,
        "redis_port": config.REDIS_PORT,
        "reachable": ping(),
        "search_module": has_search_module(),
        "index_name": config.INDEX_NAME,
        "index_exists": index_exists(),
        "vector_dimensions": config.VECTOR_DIMENSIONS,
        "stored_chunks": count_chunks() if ping() else 0,
        **info,
    }


# --- ingestion metadata ------------------------------------------------------

MANIFEST_KEY = "kb:manifest"
EMBEDDING_RECORD_KEY = "kb:embedding"

CATEGORY_BY_FILENAME = (
    ("authent", "authentication"),
    ("authoriz", "authorization"),
    ("rate_limit", "rate_limiting"),
    ("throttl", "rate_limiting"),
    ("spike", "rate_limiting"),
    ("input_valid", "input_validation"),
    ("valid", "input_validation"),
    ("log", "logging"),
    ("audit", "logging"),
    ("monitor", "logging"),
    ("gdpr", "privacy"),
    ("privacy", "privacy"),
    ("mapping", "mapping"),
)

HEADER_FIELDS = {
    "policy-name": "policy_name",
    "policy-version": "policy_version",
    "effective-date": "effective_date",
    "category": "category",
    "applies-to": "applies_to",
}


def parse_doc_header(text):
    """Read the leading `Key: Value` front-matter of a policy document.

    Unknown or absent headers yield None per field; nothing is guessed.
    """
    import re as _re
    found = {field: None for field in HEADER_FIELDS.values()}
    for line in str(text or "").splitlines():
        match = _re.match(r"\s*([A-Za-z-]+)\s*:\s*(.+?)\s*$", line)
        if not match:
            break
        field = HEADER_FIELDS.get(match.group(1).lower())
        if field and found[field] is None:
            found[field] = match.group(2)
    return found


def derive_category(filename, text=""):
    """Best-effort category: explicit header, then filename signals."""
    header = parse_doc_header(text)
    if header.get("category"):
        return header["category"].strip().lower()
    lowered = str(filename or "").lower()
    for signal, category in CATEGORY_BY_FILENAME:
        if signal in lowered:
            return category
    return "general"


def derive_version(text=""):
    """Best-effort version: explicit header, then `vX.Y` in the first lines."""
    import re as _re
    header = parse_doc_header(text)
    if header.get("policy_version"):
        return header["policy_version"].strip()
    for line in str(text or "").splitlines()[:8]:
        match = _re.search(r"\bv?(\d+\.\d+(?:\.\d+)?)", line)
        if match:
            return match.group(1)
    return None


def version_key(version):
    """Comparable version tuple; unparseable versions sort before all."""
    try:
        return tuple(int(part) for part in str(version).strip().split("."))
    except (TypeError, ValueError, AttributeError):
        return ()


def content_hash(text):
    import hashlib as _hashlib
    return _hashlib.sha1(str(text or "").encode("utf-8")).hexdigest()


def chunk_id_for(filename, index, content):
    """Deterministic chunk id: re-ingesting unchanged content reuses keys."""
    import hashlib as _hashlib
    seed = f"{filename}\0{index}\0{content_hash(content)}"
    return _hashlib.sha1(seed.encode("utf-8")).hexdigest()[:16]


def load_manifest():
    """Filename -> {content_hash, policy_version, chunk_count, ingested_at}.

    Never raises: a missing or corrupt manifest means "ingest everything".
    """
    try:
        raw = get_client().get(MANIFEST_KEY)
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        loaded = json.loads(raw or "{}")
        return loaded if isinstance(loaded, dict) else {}
    except Exception:
        return {}


def save_manifest(manifest):
    get_client().set(MANIFEST_KEY, json.dumps(manifest or {}).encode("utf-8"))
    return manifest or {}


def load_embedding_record():
    """The {provider, model, dimensions} the index was built with, if known."""
    try:
        raw = get_client().get(EMBEDDING_RECORD_KEY)
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        loaded = json.loads(raw or "null")
        return loaded if isinstance(loaded, dict) else None
    except Exception:
        return None


def save_embedding_record(provider, model, dimensions):
    record = {"provider": provider, "model": model,
              "dimensions": int(dimensions)}
    get_client().set(EMBEDDING_RECORD_KEY, json.dumps(record).encode("utf-8"))
    return record


def delete_by_source(filename):
    """Delete every chunk stored for one source file. Returns the count."""
    client = get_client()
    removed = 0
    for key in iter_keys():
        data = client.hgetall(key)
        if _decode((data or {}).get(b"source", b"")) == filename:
            client.delete(key)
            removed += 1
    return removed


# --- retrieval curation ------------------------------------------------------

FILTER_OVERSAMPLE = 3

CATEGORY_BY_POLICY = (
    ("authoriz", "authorization"),
    ("authent", "authentication"),
    ("rate", "rate_limiting"),
    ("throttl", "rate_limiting"),
    ("spike", "rate_limiting"),
    ("log", "logging"),
    ("audit", "logging"),
    ("monitor", "logging"),
    ("input", "input_validation"),
    ("valid", "input_validation"),
    ("gdpr", "privacy"),
    ("privacy", "privacy"),
    ("data", "privacy"),
)


def require_embedding_space():
    """Fail closed when the index was built with a different embedding space.

    Unknown legacy indexes (no record) proceed; a recorded mismatch raises
    with a re-ingest pointer instead of returning cross-space garbage.
    """
    from common import embeddings as embedding_mod
    record = load_embedding_record()
    if record is None:
        return True
    current = {"provider": embedding_mod.embedding_provider(),
               "model": embedding_mod.embedding_model_id(),
               "dimensions": config.VECTOR_DIMENSIONS}
    if (record.get("provider") != current["provider"]
            or record.get("model") != current["model"]
            or int(record.get("dimensions", -1)) != current["dimensions"]):
        raise RuntimeError(
            f"Embedding space mismatch: index built with {record}, current "
            f"is {current}. Re-ingest with POST /api/v1/knowledge/ingest "
            "(reset=true) before retrieving.")
    return True


def version_status_for(metadata, manifest=None, as_of=None):
    """Currency of one chunk: current | superseded | not_yet_effective | unknown.

    `as_of` is an ISO date; chunks effective after it are not yet usable.
    """
    import datetime as _dt
    metadata = metadata or {}
    effective = (metadata.get("effective_date") or "").strip()
    if effective and not _effective_ok(effective, as_of):
        return "not_yet_effective"
    version = (metadata.get("policy_version") or "").strip()
    manifest = manifest if manifest is not None else load_manifest()
    latest = ((manifest or {}).get(metadata.get("filename") or "")
              or {}).get("policy_version")
    if version and latest and version_key(version) < version_key(latest):
        return "superseded"
    if effective or version:
        return "current"
    return "unknown"


def _effective_ok(effective, as_of):
    import datetime as _dt
    try:
        day = _dt.date.fromisoformat(effective.strip()[:10])
    except (AttributeError, ValueError):
        return True
    if as_of is None:
        as_of = _dt.date.today().isoformat()
    try:
        return day <= _dt.date.fromisoformat(str(as_of)[:10])
    except ValueError:
        return True


def apply_filters(hits, filters=None, manifest=None):
    """Deterministic metadata curation. Never raises on ragged hits.

    Supported filters: category, policy_version, applies_to,
    effective_as_of (ISO date), include_superseded, include_not_effective.
    Every surviving hit gains `version_status`.
    """
    filters = filters or {}
    manifest = manifest if manifest is not None else load_manifest()
    as_of = filters.get("effective_as_of")
    wanted_category = str(filters.get("category") or "").lower() or None
    wanted_version = str(filters.get("policy_version") or "") or None
    wanted_scope = str(filters.get("applies_to") or "").lower() or None
    kept = []
    for hit in hits or []:
        if not isinstance(hit, dict):
            continue
        metadata = hit.get("metadata") or {}
        if wanted_category and str(
                metadata.get("category") or "").lower() != wanted_category:
            continue
        if wanted_version and str(
                metadata.get("policy_version") or "") != wanted_version:
            continue
        if wanted_scope and str(
                metadata.get("applies_to") or "all").lower() not in (
                    wanted_scope, "all"):
            continue
        effective = (metadata.get("effective_date") or "").strip()
        if effective and not _effective_ok(effective, as_of):
            hit["version_status"] = "not_yet_effective"
            if not filters.get("include_not_effective"):
                continue
            kept.append(hit)
            continue
        status = version_status_for(metadata, manifest, as_of)
        hit["version_status"] = status
        if status == "superseded" and not filters.get("include_superseded"):
            continue
        kept.append(hit)
    return kept


def category_for_policy(policy_name):
    """Map a finding's policy name to a retrieval category, or None."""
    lowered = str(policy_name or "").lower()
    for signal, category in CATEGORY_BY_POLICY:
        if signal in lowered:
            return category
    return None


def search_for_finding(finding, top_k=4, extra_filters=None):
    """Finding-aware retrieval: query from the finding, category filtered.

    Accepts LLM verdict, policy finding and legacy remediation shapes.
    """
    finding = finding or {}
    name = (finding.get("policy_name") or finding.get("policyName") or "")
    missing = (finding.get("missing_plugins")
               or finding.get("missingPlugins") or [])
    details = finding.get("details") or finding.get("issue") or ""
    service = finding.get("service") or finding.get("serviceName") or ""
    if not service and isinstance(finding.get("affected_api"), dict):
        service = finding["affected_api"].get("api", "")
    query = " ".join(part for part in
                     [name, " ".join(missing), details, f"service {service}"]
                     if part).strip() or name or "security policy"
    filters = dict(extra_filters or {})
    category = category_for_policy(name)
    if category and "category" not in filters:
        filters["category"] = category
    return search(query, top_k=top_k, filters=filters or None)


def assess_retrieval(hits, min_hits=1, min_best_score=0.0):
    """Sufficiency verdict over retrieved evidence. Never raises."""
    scores = [h.get("score") for h in (hits or []) if isinstance(h, dict)
              and isinstance(h.get("score"), (int, float))]
    best = max(scores) if scores else None
    reasons = []
    if len(hits or []) < min_hits:
        reasons.append(f"only {len(hits or [])} hit(s); need {min_hits}")
    if best is not None and best < min_best_score:
        reasons.append(f"best score {best} below {min_best_score}")
    if not scores and (hits or []):
        reasons.append("hits carry no similarity scores")
    return {"sufficient": not reasons, "hit_count": len(hits or []),
            "best_score": best, "reasons": reasons}


def format_excerpts(chunks, empty_text="No policy excerpts retrieved."):
    """Render retrieved chunks as delimited, source-tagged evidence blocks.

    Delimiters plus the system-prompt grounding rule keep retrieved text as
    cited evidence; instructions smuggled into a document stay visibly inside
    their quoted block instead of blending into the task prompt.
    """
    blocks = []
    items = [c for c in (chunks or []) if isinstance(c, dict)]
    for position, chunk in enumerate(items, start=1):
        metadata = chunk.get("metadata") or {}
        version = metadata.get("policy_version") or "unknown"
        blocks.append(
            f"[policy excerpt {position}/{len(items)} | "
            f"source: {chunk.get('source', '?')} | version: {version} | "
            f"similarity: {chunk.get('score', '?')}]\n"
            f"{chunk.get('content', '')}\n"
            "[/policy excerpt]")
    return "\n\n".join(blocks) if blocks else empty_text
