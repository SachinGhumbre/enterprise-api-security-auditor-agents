"""
===============================================================================
 File Name   : redis-test.py
 Description : Small Flask harness to add, list and delete embeddings stored in
               the Enterprise API Security Auditor Redis vector database.
 Author      : Sachin Ghumbre
 Version     : v1.0.0
 License     : Proprietary
 Tags        : python, redis, flask, genai, audit
===============================================================================
"""

import json
import os
import uuid

import numpy as np
from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv
import redis
from redis.commands.search.field import TagField, TextField, VectorField
from redis.commands.search.index_definition import IndexDefinition, IndexType

# Load environment variables from backend/.env (load_dotenv() alone only walks
# *up* from the cwd, so it never finds the file inside backend/).
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.getenv("ENV_FILE") or os.path.join(BASE_DIR, "backend", ".env")
load_dotenv(ENV_PATH if os.path.exists(ENV_PATH) else None)

# Flask App Initialization
app = Flask(__name__)
CORS(app)

# Constants
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
VECTOR_DIMENSIONS = int(os.getenv("VECTOR_DIMENSIONS", 1536))
INDEX_NAME = os.getenv("INDEX_NAME", "security_auditor_index")
KEY_PREFIX = "embedding:"

# Redis connection.
#
# decode_responses stays False on purpose. The knowledge ingestor stores each
# chunk's embedding in a `vector` field as packed FLOAT32 bytes, which is not
# valid UTF-8; with decode_responses=True redis-py tries to decode it on read and
# raises "'utf-8' codec can't decode byte ...". Fields are decoded individually
# below instead - the same approach as backend/common/vector_store.py.
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=False)

# Field that holds packed float32 vectors; never decoded as text.
VECTOR_FIELD = b"vector"


def _decode(value, default=""):
    """Decode a Redis value to str, tolerating non-UTF-8 bytes."""
    if value is None:
        return default
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _info_value(info, field, default=None):
    """Read a field from FT.INFO.

    With decode_responses=False the reply has bytes keys, so a plain
    info.get("num_docs") silently returns None.
    """
    if not info:
        return default
    for key in (field, field.encode()):
        if key in info:
            value = info[key]
            value = _decode(value) if isinstance(value, bytes) else value
            try:
                return int(value)
            except (TypeError, ValueError):
                return value
    return default


def iter_embedding_keys():
    """Yield every embedding key, regardless of whether the index exists."""
    return redis_client.scan_iter(match=f"{KEY_PREFIX}*", count=500)


def build_schema(dimensions=VECTOR_DIMENSIONS):
    """Schema mirroring backend/rag/knowledge_ingestor.py, plus the `text` field
    written by /redis/add_embedding."""
    return (
        TextField("content"),
        TextField("text"),
        VectorField("vector", "FLAT", {
            "TYPE": "FLOAT32",
            "DIM": dimensions,
            "DISTANCE_METRIC": "COSINE"
        }),
        TagField("metadata")
    )


def index_exists(index_name=None):
    try:
        redis_client.ft(index_name or INDEX_NAME).info()
        return True
    except Exception:
        return False


def resolve_index_name(value):
    """Validate a caller-supplied index name, falling back to INDEX_NAME."""
    if value is None:
        return INDEX_NAME, None
    if not isinstance(value, str) or not value.strip():
        return None, "'index_name' must be a non-empty string."
    name = value.strip()
    if any(c.isspace() for c in name):
        return None, "'index_name' must not contain whitespace."
    return name, None


@app.route('/redis/create_index', methods=['POST'])
def create_index():
    """Create a vector index.

    Body (all optional):
        index_name        - defaults to INDEX_NAME from backend/.env
        prefix            - key prefix to index, defaults to "embedding:"
        vector_dimensions - defaults to VECTOR_DIMENSIONS from backend/.env
        recreate          - drop and rebuild if it already exists (docs kept)
    """
    payload = request.get_json(silent=True) or {}

    index_name, error = resolve_index_name(payload.get("index_name"))
    if error:
        return jsonify({"error": error}), 400

    prefix = payload.get("prefix", KEY_PREFIX)
    if not isinstance(prefix, str) or not prefix:
        return jsonify({"error": "'prefix' must be a non-empty string."}), 400

    try:
        dimensions = int(payload.get("vector_dimensions", VECTOR_DIMENSIONS))
        if dimensions <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"error": "'vector_dimensions' must be a positive integer."}), 400

    recreate = bool(payload.get("recreate", False))

    try:
        if index_exists(index_name):
            if not recreate:
                return jsonify({
                    "message": f"Index '{index_name}' already exists.",
                    "index_name": index_name,
                    "created": False
                }), 200
            redis_client.ft(index_name).dropindex(delete_documents=False)

        definition = IndexDefinition(prefix=[prefix], index_type=IndexType.HASH)
        redis_client.ft(index_name).create_index(
            build_schema(dimensions), definition=definition
        )

        return jsonify({
            "message": f"Index '{index_name}' created.",
            "index_name": index_name,
            "prefix": prefix,
            "vector_dimensions": dimensions,
            "recreated": recreate,
            "created": True
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/redis/index_info', methods=['GET'])
def index_info():
    """Report index status and the Redis connection actually in use.

    Optional query param: ?index_name=<name> (defaults to INDEX_NAME).
    """
    index_name, error = resolve_index_name(request.args.get("index_name"))
    if error:
        return jsonify({"error": error}), 400

    try:
        info = redis_client.ft(index_name).info() if index_exists(index_name) else None
        return jsonify({
            "index_name": index_name,
            "exists": info is not None,
            "num_docs": _info_value(info, "num_docs", 0),
            "stored_keys": sum(1 for _ in iter_embedding_keys()),
            "redis_host": REDIS_HOST,
            "redis_port": REDIS_PORT,
            "env_file": ENV_PATH if os.path.exists(ENV_PATH) else None
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/redis/add_embedding', methods=['POST'])
def add_embedding():
    """Store a text/embedding pair as a Redis hash."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400

    text = payload.get("text")
    embedding = payload.get("embedding")

    if not text:
        return jsonify({"error": "'text' is required."}), 400
    if embedding is None:
        return jsonify({"error": "'embedding' is required."}), 400

    try:
        embedding_id = str(uuid.uuid4())
        redis_key = f"{KEY_PREFIX}{embedding_id}"

        redis_client.hset(redis_key, mapping={
            "text": text,
            "embedding": json.dumps(embedding)
        })

        return jsonify({
            "message": "Embedding added.",
            "id": redis_key,
            "text": text,
            "embedding": embedding
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/redis/all_embeddings', methods=['GET'])
def get_all_embeddings():
    """Return every stored embedding.

    Handles both shapes that live under the `embedding:` prefix:
      - docs from /redis/add_embedding, whose `embedding` field is a JSON blob
      - docs from the knowledge ingestor, whose `vector` field is FLOAT32 bytes

    Query params:
        include_vector=true  decode the float32 vector into a list of floats
                             (1536 numbers per chunk - large payload)
        limit=<n>            cap the number of documents returned
    """
    include_vector = request.args.get("include_vector", "false").lower() == "true"
    limit = request.args.get("limit", type=int)

    try:
        embeddings = []
        for redis_key in iter_embedding_keys():
            if limit is not None and len(embeddings) >= limit:
                break

            data = redis_client.hgetall(redis_key)
            if not data:
                continue

            raw_embedding = data.get(b"embedding")
            if raw_embedding is None:
                parsed_embedding = None
            else:
                decoded = _decode(raw_embedding)
                try:
                    parsed_embedding = json.loads(decoded)
                except (TypeError, ValueError):
                    parsed_embedding = decoded

            raw_vector = data.get(VECTOR_FIELD, b"")
            entry = {
                "id": _decode(redis_key),
                "text": _decode(data.get(b"text") or data.get(b"content")),
                "embedding": parsed_embedding,
                # 4 bytes per float32.
                "vector_dimensions": len(raw_vector) // 4,
                "metadata": {
                    _decode(k): _decode(v)
                    for k, v in data.items()
                    if k not in (b"text", b"embedding", b"content", VECTOR_FIELD)
                },
            }
            if include_vector and raw_vector:
                entry["vector"] = np.frombuffer(raw_vector, dtype=np.float32).tolist()

            embeddings.append(entry)

        return jsonify({"count": len(embeddings), "embeddings": embeddings})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/redis/all_embeddings', methods=['DELETE'])
def delete_all_embeddings():
    """Delete every stored embedding."""
    try:
        deleted_ids = []
        for redis_key in iter_embedding_keys():
            redis_client.delete(redis_key)
            deleted_ids.append(redis_key)

        return jsonify({
            "message": f"Deleted {len(deleted_ids)} embeddings.",
            "deleted_ids": deleted_ids
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5002)
