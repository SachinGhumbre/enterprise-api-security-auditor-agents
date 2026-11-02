"""Tests for resilient inventory discovery, snapshots and diffing."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config, kong_inventory, vector_store  # noqa: E402

SERVICES = [{"id": "svc-a", "name": "orders-api"}]
ROUTES = [{"id": "rt-1", "service": {"id": "svc-a"},
           "paths": ["/orders"], "methods": ["GET"]}]
PLUGINS = [{"name": "key-auth", "route": {"id": "rt-1"}},
           {"name": "rate-limiting", "service": {"id": "svc-a"}}]


class FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value):
        self.store[key] = value


def _fake_redis(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(vector_store, "get_client", lambda: fake)
    return fake


def test_partial_collect_survives_route_outage():
    def fetch(endpoint):
        if endpoint == "routes":
            raise RuntimeError("HTTP 500")
        return {"services": SERVICES, "plugins": PLUGINS}[endpoint]

    report = kong_inventory.collect_report(fetch=fetch)
    assert report["gaps"] == [{"collection": "routes", "error": "HTTP 500"}]
    (service,) = report["inventory"]
    # Service-bound and global plugins survive; route attribution is lost.
    assert service["service_plugins"] == ["rate-limiting"]
    assert service["service_routes"] == []
    assert report["collections"] == {"services": 1, "plugins": 2}


def test_partial_collect_fails_without_services():
    def fetch(endpoint):
        if endpoint == "services":
            raise RuntimeError("connection refused")
        return []

    try:
        kong_inventory.collect_report(fetch=fetch)
    except kong_inventory.KongInventoryError as exc:
        assert "services collection failed" in str(exc)
    else:
        raise AssertionError("expected KongInventoryError")


def test_snapshot_roundtrip_with_provenance(monkeypatch):
    fake = _fake_redis(monkeypatch)
    inventory = kong_inventory.join_inventory(SERVICES, ROUTES, PLUGINS)
    saved = kong_inventory.save_snapshot(inventory, "kong_admin_api")
    assert saved["environment"] == config.resolve_kong_mode()
    assert saved["count"] == 1 and saved["captured_at"]
    assert fake.get(config.KONG_SNAPSHOT_KEY)

    loaded, freshness = kong_inventory.load_snapshot()
    assert loaded["inventory"] == inventory
    assert loaded["source"] == "kong_admin_api"
    assert freshness["stale"] is False

    # Second save preserves the previous snapshot for diffing.
    kong_inventory.save_snapshot([], "kong_admin_api")
    previous = kong_inventory.load_previous()
    assert previous["count"] == 1


def test_snapshot_load_never_raises(monkeypatch):
    fake = _fake_redis(monkeypatch)
    assert kong_inventory.load_snapshot() == (None, None)
    fake.set(config.KONG_SNAPSHOT_KEY, b"not json{{{")
    assert kong_inventory.load_snapshot() == (None, None)

    def boom():
        raise RuntimeError("redis down")

    monkeypatch.setattr(vector_store, "get_client", boom)
    assert kong_inventory.load_snapshot() == (None, None)
    assert kong_inventory.load_previous() is None


def test_snapshot_staleness_uses_configured_horizon(monkeypatch):
    fake = _fake_redis(monkeypatch)
    monkeypatch.setattr(config, "KONG_SNAPSHOT_STALE_S", 60)
    fake.set(config.KONG_SNAPSHOT_KEY, json.dumps({
        "captured_at": "2000-01-01T00:00:00+00:00", "inventory": []}).encode())
    _, freshness = kong_inventory.load_snapshot()
    assert freshness["stale"] is True
    assert freshness["age_s"] > 60


def test_diff_detects_membership_and_plugin_changes():
    old = kong_inventory.join_inventory(
        SERVICES + [{"id": "svc-old", "name": "legacy"}], ROUTES, PLUGINS)
    new = kong_inventory.join_inventory(
        SERVICES + [{"id": "svc-b", "name": "payments"}], ROUTES,
        [{"name": "jwt", "service": {"id": "svc-a"}}])
    diff = kong_inventory.diff_snapshots(old, new)
    assert diff["services_added"] == ["payments"]
    assert diff["services_removed"] == ["legacy"]
    (changed,) = [c for c in diff["changed"]
                  if c["service"] == "orders-api"]
    assert changed["plugins_added"] == ["jwt"]
    assert sorted(changed["plugins_removed"]) == ["key-auth", "rate-limiting"]
    assert diff["unchanged"] is False
    assert kong_inventory.diff_snapshots(old, old)["unchanged"] is True


def test_probe_reports_unsupported_collections():
    def fetch(endpoint):
        raise RuntimeError("404")

    result = kong_inventory.probe_collection("consumers", fetch=fetch)
    assert result == {"collection": "consumers", "supported": False,
                      "error": "404"}
    ok = kong_inventory.probe_collection(
        "consumers", fetch=lambda endpoint: [{"id": "c1"}])
    assert ok == {"collection": "consumers", "supported": True, "count": 1}
