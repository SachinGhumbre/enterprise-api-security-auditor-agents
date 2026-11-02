"""
===============================================================================
 File Name   : common/embeddings.py
 Description : Embedding provider with an offline fallback so the RAG pipeline
               stays testable when no Azure embeddings deployment exists.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import hashlib
import re

import numpy as np

from . import config

_azure_client = None


def _get_azure_client():
    global _azure_client
    if _azure_client is None:
        from openai import AzureOpenAI
        _azure_client = AzureOpenAI(
            api_version=config.AZURE_API_VERSION,
            azure_endpoint=config.AZURE_OPENAI_ENDPOINT,
            api_key=config.AZURE_OPENAI_API_KEY,
        )
    return _azure_client


_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _local_embedding(text, dimensions):
    """Deterministic hashed bag-of-words vector.

    This is a LEXICAL embedding, not a semantic one: it matches on shared
    vocabulary, so retrieval still works for keyword-style policy lookups, but
    it cannot capture paraphrase the way a real embedding model does. Intended
    for offline demos and CI, never for production retrieval quality.
    """
    vector = np.zeros(dimensions, dtype=np.float32)
    tokens = _TOKEN_RE.findall(text.lower())
    if not tokens:
        return vector

    for token in tokens:
        for gram in (token, token[:4]):
            digest = hashlib.blake2b(gram.encode("utf-8"), digest_size=8).digest()
            bucket = int.from_bytes(digest[:4], "big") % dimensions
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            vector[bucket] += sign

    norm = float(np.linalg.norm(vector))
    return vector / norm if norm else vector


def embedding_provider():
    return config.resolve_embedding_provider()


def embedding_model_id():
    """Stable id of the model backing embed(): deployment or "local"."""
    if embedding_provider() == "local":
        return "local"
    return config.AZURE_OPENAI_EMBEDDING_DEPLOYMENT or "azure-unknown"


def check_config():
    """Return a list of human-readable configuration problems (empty when OK)."""
    if embedding_provider() == "local":
        return []

    missing = [name for name, value in (
        ("AZURE_OPENAI_API_KEY", config.AZURE_OPENAI_API_KEY),
        ("AZURE_OPENAI_ENDPOINT", config.AZURE_OPENAI_ENDPOINT),
        ("AZURE_API_VERSION", config.AZURE_API_VERSION),
        ("AZURE_OPENAI_EMBEDDING_DEPLOYMENT", config.AZURE_OPENAI_EMBEDDING_DEPLOYMENT),
    ) if not value]

    if missing:
        return [
            "Missing environment variable(s) in backend/.env: "
            f"{', '.join(missing)}. AZURE_OPENAI_EMBEDDING_DEPLOYMENT must name an "
            "*embeddings* deployment (e.g. text-embedding-3-small); a chat deployment "
            "such as gpt-5.5 returns OperationNotSupported. Set "
            "EMBEDDING_PROVIDER=local to run without Azure embeddings."
        ]
    return []


def embed(text, dimensions=None):
    """Return a list[float] embedding for `text`."""
    dimensions = dimensions or config.VECTOR_DIMENSIONS

    if embedding_provider() == "local":
        return _local_embedding(text, dimensions).tolist()

    response = _get_azure_client().embeddings.create(
        input=[text],
        model=config.AZURE_OPENAI_EMBEDDING_DEPLOYMENT,
    )
    return response.data[0].embedding


def embed_batch(texts, dimensions=None):
    dimensions = dimensions or config.VECTOR_DIMENSIONS

    if embedding_provider() == "local":
        return [_local_embedding(t, dimensions).tolist() for t in texts]

    response = _get_azure_client().embeddings.create(
        input=list(texts),
        model=config.AZURE_OPENAI_EMBEDDING_DEPLOYMENT,
    )
    return [item.embedding for item in response.data]


def to_bytes(embedding):
    return np.asarray(embedding, dtype=np.float32).tobytes()


def from_bytes(raw):
    return np.frombuffer(raw, dtype=np.float32).tolist()
