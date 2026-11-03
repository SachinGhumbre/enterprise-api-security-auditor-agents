"""Security regression tests for API-key auth and roles."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import auth, config  # noqa: E402


def _keys(monkeypatch, admin=("adm-1",), operator=("op-1",), viewer=("view-1",)):
    monkeypatch.setattr(config, "ADMIN_API_KEYS", list(admin))
    monkeypatch.setattr(config, "OPERATOR_API_KEYS", list(operator))
    monkeypatch.setattr(config, "VIEWER_API_KEYS", list(viewer))


def test_auth_disabled_without_keys(monkeypatch):
    _keys(monkeypatch, admin=(), operator=(), viewer=())
    assert auth.auth_enabled() is False
    from agents.init_auditor import app as flask_app
    assert flask_app.test_client().get(
        "/api/v1/ai-agents/llm/calls").status_code in (200, 400)


def test_identify_accepts_bearer_and_header(monkeypatch):
    _keys(monkeypatch)
    role, fingerprint = auth.identify({"Authorization": "Bearer adm-1"})
    assert role == "admin" and len(fingerprint) == 12
    role, _ = auth.identify({"X-API-Key": "view-1"})
    assert role == "viewer"
    assert auth.identify({}) == (None, None)
    assert auth.identify({"Authorization": "Bearer wrong"}) == (None, None)
    assert auth.fingerprint("adm-1") != "adm-1"  # never the key itself


def test_agents_app_enforces_roles(monkeypatch):
    _keys(monkeypatch)
    from common import vector_store
    monkeypatch.setattr(vector_store, "ping", lambda: False)
    from agents.init_auditor import app as flask_app
    client = flask_app.test_client()

    assert client.get("/api/v1/ai-agents/health").status_code == 200
    assert client.get("/api/v1/ai-agents/llm/calls").status_code == 401
    assert client.get("/api/v1/ai-agents/llm/calls",
                      headers={"X-API-Key": "view-1"}).status_code == 200

    denied = client.post("/api/v1/ai-agents/assess", json={},
                         headers={"X-API-Key": "view-1"})
    assert denied.status_code == 403  # viewer cannot start assessments

    bad_key = client.post("/api/v1/ai-agents/assess", json={},
                          headers={"X-API-Key": "nope"})
    assert bad_key.status_code == 401


def test_knowledge_app_enforces_roles(monkeypatch):
    _keys(monkeypatch)
    from common import vector_store
    monkeypatch.setattr(vector_store, "index_exists", lambda *a, **k: False)
    monkeypatch.setattr(vector_store, "ping", lambda: False)
    from rag.knowledge_ingestor import app as flask_app
    client = flask_app.test_client()

    assert client.get("/api/v1/knowledge/health").status_code in (200, 503)
    assert client.post("/api/v1/knowledge/ingest", json={},
                       headers={"X-API-Key": "op-1"}).status_code == 403
    assert client.delete("/api/v1/knowledge/embeddings",
                         headers={"X-API-Key": "op-1"}).status_code == 403
    assert client.post("/api/v1/knowledge/search", json={"query": "x"},
                       headers={"X-API-Key": "view-1"}).status_code != 401


def test_live_execution_requires_admin(monkeypatch):
    _keys(monkeypatch)
    from agents.init_auditor import app as flask_app
    client = flask_app.test_client()
    response = client.post(
        "/api/v1/ai-agents/assess/any-id/changes/any-change/execute",
        json={"mode": "live"}, headers={"X-API-Key": "op-1"})
    assert response.status_code == 403
    assert "admin" in response.get_json()["error"]
    simulated = client.post(
        "/api/v1/ai-agents/assess/any-id/changes/any-change/execute",
        json={"mode": "simulate"}, headers={"X-API-Key": "op-1"})
    assert simulated.status_code == 404  # role ok, id unknown


def test_redis_client_uses_configured_username(monkeypatch):
    import redis
    import common.vector_store as vector_store
    seen = {}
    real_redis = redis.Redis

    def capture(*args, **kwargs):
        seen.update(kwargs)
        raise RuntimeError("stop here")

    monkeypatch.setattr(redis, "Redis", capture)
    monkeypatch.setattr(vector_store, "_client", None)
    monkeypatch.setattr(config, "REDIS_USERNAME", "auditor-ro")
    try:
        vector_store.get_client()
    except RuntimeError:
        pass
    finally:
        monkeypatch.setattr(vector_store, "_client", None)
    assert seen.get("username") == "auditor-ro"
    assert real_redis is not None


def test_options_preflight_bypasses_auth(monkeypatch):
    """CORS preflights carry no credentials by design; 401ing them blocks
    every cross-origin dashboard call that sends an API-key header."""
    _keys(monkeypatch)
    from agents.init_auditor import app as agents_app
    from rag.knowledge_ingestor import app as knowledge_app

    agents = agents_app.test_client()
    assert agents.get("/api/v1/ai-agents/assistant/prompts").status_code == 401
    preflight = agents.options("/api/v1/ai-agents/assistant/prompts")
    assert preflight.status_code == 200
    assert "Access-Control-Allow-Origin" in preflight.headers

    knowledge = knowledge_app.test_client()
    assert knowledge.options("/api/v1/knowledge/search").status_code == 200
