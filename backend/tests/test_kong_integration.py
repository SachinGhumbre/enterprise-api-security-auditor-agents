"""Integration tests for Kong discovery with mocked gateway responses.

HTTP and Redis are stubbed, but the real transport, join, snapshot and
discovery code runs end to end. No stub_env: the discovery node uses its
production tool wiring.
"""

import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents import orchestrator  # noqa: E402
from common import config, kong_inventory, vector_store  # noqa: E402

KONNECT_API = "https://eu.api.konghq.com/v2/control-planes/cp1"

SERVICES_PAGES = [
    {"data": [{"id": "svc-a", "name": "orders-api"}], "offset": "p2"},
    {"data": [{"id": "svc-b", "name": "Healthcheck"}]},
]
ROUTES = {"data": [
    {"id": "rt-1", "service": {"id": "svc-a"}, "paths": ["/orders"],
     "methods": ["GET"]},
    {"id": "rt-2", "service": {"id": "svc-b"}, "paths": ["/health"],
     "methods": ["GET"]},
]}
PLUGINS = {"data": [
    {"name": "key-auth", "route": {"id": "rt-1"}},
    {"name": "rate-limiting", "service": {"id": "svc-a"}},
    {"name": "correlation-id"},
    {"name": "acl", "consumer": {"id": "c1"}},
]}
CONSUMERS = {"data": [{"id": "c1", "username": "mobile-app"}]}


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.headers = {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


class FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value):
        self.store[key] = value


def _kong_env(monkeypatch, routes_status=200):
    monkeypatch.setattr(config, "KONG_ADMIN_MODE", "konnect")
    monkeypatch.setattr(config, "KONG_ADMIN_API", KONNECT_API)
    monkeypatch.setattr(config, "KONG_ADMIN_TOKEN", "test-token-1")
    monkeypatch.setattr(config, "KONG_MAX_RETRIES", 0)
    monkeypatch.setattr(config, "KONG_RETRY_BACKOFF_S", 0)
    calls = []

    def fake_get(url, headers=None, params=None, **kwargs):
        calls.append(url)
        assert headers == {"Authorization": "Bearer test-token-1"}
        if "core-entities/services" in url:
            page = 1 if (params or {}).get("offset") else 0
            return FakeResponse(SERVICES_PAGES[page])
        if "core-entities/routes" in url:
            return FakeResponse(ROUTES, routes_status)
        if "core-entities/plugins" in url:
            return FakeResponse(PLUGINS)
        if "core-entities/consumers" in url:
            return FakeResponse(CONSUMERS)
        raise AssertionError(f"unexpected url {url}")

    monkeypatch.setattr(requests, "get", fake_get)
    fake = FakeRedis()
    monkeypatch.setattr(vector_store, "get_client", lambda: fake)
    return fake, calls


def test_mocked_konnect_flow_end_to_end(monkeypatch):
    fake, calls = _kong_env(monkeypatch)
    report = kong_inventory.collect_report()
    assert report["gaps"] == []
    by_name = {s["service_name"]: s for s in report["inventory"]}
    assert by_name["orders-api"]["service_plugins"] == [
        "correlation-id", "key-auth", "rate-limiting"]
    assert by_name["Healthcheck"]["service_plugins"] == ["correlation-id"]
    assert by_name["orders-api"]["service_routes"][0]["paths"] == ["/orders"]

    saved = kong_inventory.save_snapshot(report["inventory"], "kong_admin_api",
                                         gaps=report["gaps"])
    assert saved["environment"] == "konnect"
    loaded, freshness = kong_inventory.load_snapshot()
    assert loaded["count"] == 2 and freshness["stale"] is False

    evolved = [dict(s) for s in report["inventory"]]
    evolved[0]["service_plugins"] = ["correlation-id", "jwt", "rate-limiting"]
    diff = kong_inventory.diff_snapshots(loaded["inventory"], evolved)
    assert diff["services_added"] == [] and diff["unchanged"] is False
    changed = {c["service"]: c for c in diff["changed"]}
    assert changed["orders-api"]["plugins_added"] == ["jwt"]
    assert any("core-entities/services" in c for c in calls)


def test_discovery_node_with_real_tools_caches_snapshot(monkeypatch):
    fake, _ = _kong_env(monkeypatch)
    updates = orchestrator.discovery({"service_names": None, "top_k": 1,
                                      "budgets": {}, "max_retries": 0})
    assert updates["kong_source"] == "kong_admin_api"
    assert updates["kong_live"] is True
    assert updates["kong_gaps"] == []
    assert updates["kong_capabilities"] == {
        "services": True, "routes": True, "plugins": True,
        "consumers": True}
    assert updates["kong_consumers"] == [{"id": "c1", "username": "mobile-app",
                                          "custom_id": None}]
    assert fake.get(config.KONG_SNAPSHOT_KEY) is not None
    # Policy retrieval is honestly degraded (no vector index in FakeRedis).
    assert updates["agents"]["discovery"]["status"] == "degraded"


def test_discovery_node_survives_partial_collection(monkeypatch):
    _kong_env(monkeypatch, routes_status=500)
    updates = orchestrator.discovery({"service_names": None, "top_k": 1,
                                      "budgets": {}, "max_retries": 0})
    assert updates["kong_live"] is True  # partial live beats cached
    assert updates["kong_gaps"] == [{"collection": "routes",
                                     "error": "HTTP 500"}]
    assert updates["kong_capabilities"]["routes"] is False
    assert any("partial" in w for w in updates["warnings"])


def test_services_endpoint_serves_live_then_snapshot(monkeypatch):
    from agents.init_auditor import app as flask_app
    fake, _ = _kong_env(monkeypatch)
    client = flask_app.test_client()

    live = client.get("/api/v1/ai-agents/kong/services")
    assert live.status_code == 200
    body = live.get_json()
    assert body["live"] is True and body["stale"] is False
    assert body["count"] == 2 and body["gaps"] == []

    def down(*args, **kwargs):
        raise requests.exceptions.ConnectionError("gone")

    monkeypatch.setattr(requests, "get", down)
    cached = client.get("/api/v1/ai-agents/kong/services")
    assert cached.status_code == 200
    body = cached.get_json()
    assert body["source"] == "redis_snapshot"
    assert body["live"] is False
    assert body["count"] == 2
    assert "instead of live data" in body["warning"]


def test_inventory_module_has_no_write_path():
    import inspect
    source = inspect.getsource(kong_inventory)
    assert "kong_adapter" not in source
    assert "import requests" not in source
    assert "requests.post" not in source and "requests.delete" not in source
