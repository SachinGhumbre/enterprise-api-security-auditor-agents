"""Tests for versioned, deduplicated policy ingestion."""

import fnmatch
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import vector_store  # noqa: E402
from common import embeddings as embedding_mod  # noqa: E402


class FakeRedis:
    def __init__(self):
        self.store = {}

    def ping(self):
        return True

    def hset(self, key, mapping=None, **kwargs):
        hash_key = key if isinstance(key, bytes) else str(key).encode()
        slot = self.store.setdefault(hash_key, {})
        for field, value in dict(mapping or {}).items():
            field = field if isinstance(field, bytes) else str(field).encode()
            slot[field] = value if isinstance(value, bytes) else str(value).encode()
        return len(mapping or {})

    def hgetall(self, key):
        key = key if isinstance(key, bytes) else str(key).encode()
        return dict(self.store.get(key, {}))

    def scan_iter(self, match=None, count=None):
        for key in list(self.store.keys()):
            name = key.decode() if isinstance(key, bytes) else key
            if match is None or fnmatch.fnmatch(name, match):
                yield key

    def get(self, key):
        key = key if isinstance(key, bytes) else str(key).encode()
        return self.store.get(key)

    def set(self, key, value):
        key = key if isinstance(key, bytes) else str(key).encode()
        self.store[key] = value

    def delete(self, key):
        key = key if isinstance(key, bytes) else str(key).encode()
        return 1 if self.store.pop(key, None) is not None else 0


def _fake_env(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(vector_store, "get_client", lambda: fake)
    monkeypatch.setattr(vector_store, "ensure_index", lambda: False)
    monkeypatch.setattr(embedding_mod, "embedding_provider", lambda: "local")
    return fake


AUTH_DOC = """Policy-Name: Authentication Policy
Policy-Version: 1.0
Effective-Date: 2025-01-15
Category: authentication
Applies-To: all

Services must enable jwt or oauth2 for token-based authentication."""

RATE_DOC = """Policy Name: Rate Limiting Policy v1.2
Services must enable the rate-limiting plugin to cap request bursts."""


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_header_parsing_and_derivation():
    header = vector_store.parse_doc_header(AUTH_DOC)
    assert header == {"policy_name": "Authentication Policy",
                      "policy_version": "1.0",
                      "effective_date": "2025-01-15",
                      "category": "authentication",
                      "applies_to": "all"}
    assert vector_store.parse_doc_header("no headers here") == {
        "policy_name": None, "policy_version": None,
        "effective_date": None, "category": None, "applies_to": None}
    assert vector_store.derive_category("03_rate_limiting.txt") == "rate_limiting"
    assert vector_store.derive_version(RATE_DOC) == "1.2"
    assert vector_store.derive_version("nothing versioned") is None
    assert vector_store.version_key("1.10") > vector_store.version_key("1.2")
    assert vector_store.version_key("bogus") == ()
    first = vector_store.chunk_id_for("a.txt", 0, "hello")
    assert first == vector_store.chunk_id_for("a.txt", 0, "hello")
    assert first != vector_store.chunk_id_for("a.txt", 1, "hello")


def _ingest_client(monkeypatch, tmp_path):
    _fake_env(monkeypatch)
    _write(tmp_path, "01_auth.txt", AUTH_DOC)
    _write(tmp_path, "03_rate_limiting.txt", RATE_DOC)
    from rag.knowledge_ingestor import app as flask_app
    client = flask_app.test_client()
    response = client.post("/api/v1/knowledge/ingest",
                           json={"knowledge_dir": str(tmp_path)})
    assert response.status_code == 200
    return client, response.get_json()


def test_ingest_stores_versioned_metadata(monkeypatch, tmp_path):
    _, body = _ingest_client(monkeypatch, tmp_path)
    assert body["total_chunks"] == 2
    assert {f["action"] for f in body["files"]} == {"ingested"}
    chunks = vector_store.list_chunks()
    by_file = {c["metadata"]["filename"]: c for c in chunks}
    auth = by_file["01_auth.txt"]["metadata"]
    assert auth["policy_version"] == "1.0"
    assert auth["category"] == "authentication"
    assert auth["effective_date"] == "2025-01-15"
    assert auth["embedding_provider"] == "local"
    assert auth["embedding_model"] == "local"
    assert auth["content_hash"]
    rate = by_file["03_rate_limiting.txt"]["metadata"]
    assert rate["policy_version"] == "1.2"  # regex fallback, no headers
    assert rate["category"] == "rate_limiting"  # filename fallback
    manifest = json.loads(
        vector_store.get_client().get("kb:manifest").decode())
    assert set(manifest) == {"01_auth.txt", "03_rate_limiting.txt"}
    record = json.loads(
        vector_store.get_client().get("kb:embedding").decode())
    assert record["provider"] == "local"


def test_reingest_skips_unchanged_files(monkeypatch, tmp_path):
    client, _ = _ingest_client(monkeypatch, tmp_path)
    before = vector_store.list_chunks()
    response = client.post("/api/v1/knowledge/ingest",
                           json={"knowledge_dir": str(tmp_path)})
    body = response.get_json()
    assert {f["action"] for f in body["files"]} == {"skipped"}
    after = vector_store.list_chunks()
    assert len(after) == len(before) == 2  # no duplicates
    assert {c["id"] for c in after} == {c["id"] for c in before}


def test_changed_file_is_reindexed(monkeypatch, tmp_path):
    client, _ = _ingest_client(monkeypatch, tmp_path)
    _write(tmp_path, "01_auth.txt", AUTH_DOC.replace("1.0", "2.0"))
    response = client.post("/api/v1/knowledge/ingest",
                           json={"knowledge_dir": str(tmp_path)})
    body = response.get_json()
    actions = {f["file"]: f["action"] for f in body["files"]}
    assert actions == {"01_auth.txt": "reindexed",
                         "03_rate_limiting.txt": "skipped"}
    chunks = vector_store.list_chunks()
    assert len(chunks) == 2  # old chunk replaced, not duplicated
    versions = {c["metadata"]["policy_version"] for c in chunks}
    assert versions == {"2.0", "1.2"}


def test_reset_reingests_everything(monkeypatch, tmp_path):
    client, _ = _ingest_client(monkeypatch, tmp_path)
    response = client.post("/api/v1/knowledge/ingest",
                           json={"knowledge_dir": str(tmp_path), "reset": True})
    body = response.get_json()
    assert {f["action"] for f in body["files"]} == {"ingested"}
    assert len(vector_store.list_chunks()) == 2


def test_ingest_and_delete_are_audited(monkeypatch, tmp_path):
    import json as _json
    from common import audit_log
    log = str(tmp_path / "audit.log.jsonl")
    monkeypatch.setattr(audit_log, "AUDIT_LOG_FILE", log)
    client, _ = _ingest_client(monkeypatch, tmp_path)
    deleted = client.delete("/api/v1/knowledge/embeddings")
    assert deleted.status_code == 200
    events = [_json.loads(line) for line in open(log, encoding="utf-8")]
    assert [e["event"] for e in events] == ["knowledge.ingested",
                                            "knowledge.deleted"]
    assert events[0]["details"]["total_chunks"] == 2
    assert audit_log.verify()["ok"] is True
    assert vector_store.load_manifest() == {}  # delete resets the manifest
    assert vector_store.list_chunks() == []


def test_delete_by_source_is_scoped(monkeypatch, tmp_path):
    _ingest_client(monkeypatch, tmp_path)
    assert vector_store.delete_by_source("01_auth.txt") == 1
    remaining = vector_store.list_chunks()
    assert [c["source"] for c in remaining] == ["03_rate_limiting.txt"]
    assert vector_store.delete_by_source("missing.txt") == 0
