"""
===============================================================================
 File Name   : knowledge_ingestor.py
 Description : Enterprise API Security Auditor knowledge ingestor. Chunks the
               security policy corpus, embeds it and stores it in the Redis
               Stack vector database. Also exposes the retrieval half of the
               RAG pipeline so it can be verified independently.
 Author      : Sachin Ghumbre
 Created On  : 2025-09-26
 Version     : v1.0.0
 License     : Proprietary
 Tags        : python, redis, kong, konnect, genai, audit, langgraph, agentic ai
===============================================================================
"""

import os
import sys
import time

from flask import Flask, jsonify, request
from flask_cors import CORS

# Allow `python rag/knowledge_ingestor.py` from any working directory.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config, embeddings, vector_store  # noqa: E402

API_PREFIX = "/api/v1/knowledge"
SERVICE_PORT = config.get_int("KNOWLEDGE_PORT", 5001)

app = Flask(__name__)
CORS(app)


# --- Chunking ----------------------------------------------------------------

def chunk_text(text, size=None, overlap=None):
    """Split on word boundaries with overlap.

    The original fixed-width slice cut words and sentences in half, which
    degrades both embedding quality and the readability of retrieved context.
    """
    size = size or config.CHUNK_SIZE
    overlap = overlap if overlap is not None else config.CHUNK_OVERLAP
    text = (text or "").strip()
    if not text:
        return []
    if len(text) <= size:
        return [text]

    chunks, start = [], 0
    while start < len(text):
        end = min(start + size, len(text))
        if end < len(text):
            boundary = text.rfind(" ", start + int(size * 0.6), end)
            if boundary != -1:
                end = boundary
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return chunks


def iter_knowledge_files(root):
    """Walk the knowledge base recursively, skipping duplicates and binaries."""
    allowed = {".txt", ".md", ".markdown", ".json", ".yaml", ".yml"}
    for dirpath, dirnames, filenames in os.walk(root):
        # knowledge_base/ALL duplicates the top-level policy files verbatim;
        # ingesting both doubles every chunk and skews retrieval.
        dirnames[:] = [d for d in dirnames if d.upper() != "ALL"]
        for filename in sorted(filenames):
            if os.path.splitext(filename)[1].lower() in allowed:
                yield os.path.join(dirpath, filename)


# --- Routes -------------------------------------------------------------------

@app.route(f"{API_PREFIX}/health", methods=["GET"])
def health():
    """Readiness probe covering every downstream dependency."""
    problems = embeddings.check_config()
    redis_ok = vector_store.ping()
    if not redis_ok:
        problems.append(
            f"Cannot reach Redis at {config.REDIS_HOST}:{config.REDIS_PORT}."
        )
    elif not vector_store.has_search_module():
        problems.append(
            "Redis is reachable but the RediSearch module is missing. Use the "
            "redis/redis-stack-server image, not plain redis."
        )
    if not os.path.isdir(config.KNOWLEDGE_DIR):
        problems.append(f"Knowledge base directory not found: {config.KNOWLEDGE_DIR}")

    return jsonify({
        "service": "knowledge-ingestor",
        "status": "ok" if not problems else "degraded",
        "problems": problems,
        "config": config.summary(),
    }), (200 if not problems else 503)


@app.route(f"{API_PREFIX}/index", methods=["POST"])
def create_index():
    """Create the Redis vector index."""
    payload = request.get_json(silent=True) or {}
    try:
        created, detail = vector_store.create_index(
            index_name=payload.get("index_name"),
            prefix=payload.get("prefix"),
            dimensions=payload.get("vector_dimensions"),
            recreate=bool(payload.get("recreate", False)),
        )
        return jsonify({"created": created, **detail}), (201 if created else 200)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route(f"{API_PREFIX}/ingest", methods=["POST"])
def ingest_knowledge_base():
    """Chunk, embed and store every policy document."""
    payload = request.get_json(silent=True) or {}
    knowledge_dir = payload.get("knowledge_dir") or config.KNOWLEDGE_DIR

    if not os.path.isdir(knowledge_dir):
        return jsonify({"error": f"Knowledge base directory not found: {knowledge_dir}"}), 404

    problems = embeddings.check_config()
    if problems:
        return jsonify({"error": problems[0], "provider": embeddings.embedding_provider()}), 500

    if not vector_store.ping():
        return jsonify({
            "error": f"Cannot reach Redis at {config.REDIS_HOST}:{config.REDIS_PORT}."
        }), 503

    started = time.time()

    try:
        if bool(payload.get("reset", False)):
            vector_store.delete_all()
        vector_store.ensure_index()
    except Exception as exc:
        return jsonify({"error": f"Index preparation failed: {exc}"}), 500

    files, chunk_details, total_chunks = [], [], 0

    for file_path in iter_knowledge_files(knowledge_dir):
        filename = os.path.relpath(file_path, knowledge_dir).replace("\\", "/")
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
                content = handle.read()
        except OSError as exc:
            return jsonify({"error": f"Could not read {filename}: {exc}"}), 500

        chunks = chunk_text(content)
        if not chunks:
            files.append({"file": filename, "chunks": 0, "skipped": "empty"})
            continue

        try:
            vectors = embeddings.embed_batch(chunks)
        except Exception as exc:
            return jsonify({
                "error": f"Embedding failed for {filename}: {exc}",
                "provider": embeddings.embedding_provider(),
                "deployment": config.AZURE_OPENAI_EMBEDDING_DEPLOYMENT,
                "endpoint": config.AZURE_OPENAI_ENDPOINT,
                "hint": ("A 404/DeploymentNotFound means AZURE_OPENAI_EMBEDDING_DEPLOYMENT "
                         "does not name an existing embeddings deployment on this endpoint. "
                         "Set EMBEDDING_PROVIDER=local to ingest without Azure."),
            }), 500

        for position, (chunk, vector) in enumerate(zip(chunks, vectors)):
            if len(vector) != config.VECTOR_DIMENSIONS:
                return jsonify({
                    "error": (f"Embedding dimension mismatch for {filename}: model returned "
                              f"{len(vector)}, VECTOR_DIMENSIONS is {config.VECTOR_DIMENSIONS}."),
                    "hint": "text-embedding-3-small=1536, text-embedding-3-large=3072.",
                }), 500

            metadata = {
                "filename": filename,
                "chunk_index": position,
                "chunk_count": len(chunks),
                "timestamp": time.time(),
                "source": "security_policies",
                "embedding_provider": embeddings.embedding_provider(),
            }
            chunk_id, redis_key = vector_store.upsert_chunk(
                content=chunk, metadata=metadata, embedding=vector, source=filename
            )
            total_chunks += 1
            chunk_details.append({
                "chunk_id": chunk_id,
                "id": redis_key,
                "index_name": config.INDEX_NAME,
                "file": filename,
                "content": chunk,
                "metadata": metadata,
            })

        files.append({"file": filename, "chunks": len(chunks)})

    return jsonify({
        "message": "Ingestion complete",
        "index_name": config.INDEX_NAME,
        "embedding_provider": embeddings.embedding_provider(),
        "vector_dimensions": config.VECTOR_DIMENSIONS,
        "files_processed": len(files),
        "total_chunks": total_chunks,
        "elapsed_seconds": round(time.time() - started, 2),
        "files": files,
        "chunks": chunk_details,
    }), 200


@app.route(f"{API_PREFIX}/search", methods=["POST"])
def search_knowledge_base():
    """Vector similarity search - the retrieval half of the RAG pipeline."""
    payload = request.get_json(silent=True) or {}
    query = payload.get("query") or payload.get("text")
    if not query:
        return jsonify({"error": "'query' is required."}), 400

    try:
        top_k = int(payload.get("top_k", 5))
        if top_k <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"error": "'top_k' must be a positive integer."}), 400

    if not vector_store.index_exists():
        return jsonify({
            "error": f"Index '{config.INDEX_NAME}' does not exist. "
                     f"Run POST {API_PREFIX}/ingest first."
        }), 404

    try:
        results = vector_store.search(query, top_k=top_k)
        return jsonify({
            "query": query,
            "top_k": top_k,
            "count": len(results),
            "embedding_provider": embeddings.embedding_provider(),
            "results": results,
        }), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route(f"{API_PREFIX}/get_all_embeddings", methods=["GET"])
def get_all_embeddings():
    """Inventory of stored chunks. Pass ?include_vector=true for raw floats."""
    include_vector = request.args.get("include_vector", "false").lower() == "true"
    limit = request.args.get("limit", type=int)
    try:
        chunks = vector_store.list_chunks(limit=limit, include_vector=include_vector)
        return jsonify({
            "count": len(chunks),
            "index_name": config.INDEX_NAME,
            "embeddings": chunks,
        }), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route(f"{API_PREFIX}/stats", methods=["GET"])
def knowledge_stats():
    try:
        return jsonify(vector_store.stats()), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route(f"{API_PREFIX}/embeddings", methods=["DELETE"])
@app.route(f"{API_PREFIX}/all_embeddings", methods=["DELETE"])
def delete_all_embeddings():
    """Remove every stored chunk. The index definition is left in place."""
    try:
        deleted = vector_store.delete_all()
        return jsonify({
            "message": f"Deleted {len(deleted)} embeddings.",
            "deleted_count": len(deleted),
            "deleted_ids": deleted,
        }), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    print(f"[knowledge-ingestor] env       : {config.ENV_PATH}")
    print(f"[knowledge-ingestor] redis     : {config.REDIS_HOST}:{config.REDIS_PORT}")
    print(f"[knowledge-ingestor] embeddings: {embeddings.embedding_provider()}")
    print(f"[knowledge-ingestor] knowledge : {config.KNOWLEDGE_DIR}")
    print(f"[knowledge-ingestor] listening : http://localhost:{SERVICE_PORT}{API_PREFIX}")
    app.run(host="0.0.0.0", port=SERVICE_PORT, debug=False)
