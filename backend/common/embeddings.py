"""
===============================================================================
 File Name   : common/embeddings.py
 Description : Offline embedding provider so the RAG pipeline stays
               testable with no external embedding service.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import hashlib
import re

import numpy as np

from . import config

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
    """Stable id of the model backing embed()."""
    return "local"


def check_config():
    """Return a list of human-readable configuration problems (empty when OK)."""
    return []


def embed(text, dimensions=None):
    """Return a list[float] embedding for `text`."""
    dimensions = dimensions or config.VECTOR_DIMENSIONS
    return _local_embedding(text, dimensions).tolist()


def embed_batch(texts, dimensions=None):
    dimensions = dimensions or config.VECTOR_DIMENSIONS
    return [_local_embedding(t, dimensions).tolist() for t in texts]


def to_bytes(embedding):
    return np.asarray(embedding, dtype=np.float32).tobytes()


def from_bytes(raw):
    return np.frombuffer(raw, dtype=np.float32).tolist()
