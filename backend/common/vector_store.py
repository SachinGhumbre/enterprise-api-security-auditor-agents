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


def search(query_text, top_k=5):
    """Cosine KNN search. Returns chunks ordered most-similar first."""
    ensure_index()
    vector = embeddings.embed(query_text)

    query = (
        Query(f"*=>[KNN {int(top_k)} @vector $vec AS score]")
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
    return hits


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
