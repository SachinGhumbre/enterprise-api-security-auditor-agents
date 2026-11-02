"""Tests for the Kong Admin API client layer.

Covers the differences between Kong Konnect (Bearer PAT, /core-entities/ paths)
and a self-managed Admin API (kong-admin-token, bare paths), plus pagination and
the service/route/plugin join. All HTTP is stubbed.
"""

import os
import sys

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents import auditor_agent  # noqa: E402
from common import config  # noqa: E402


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


# --- auth header / entity path -------------------------------------------------

def test_konnect_mode_uses_bearer_and_core_entities(monkeypatch):
    monkeypatch.setattr(config, "KONG_ADMIN_MODE", "konnect")
    monkeypatch.setattr(config, "KONG_ADMIN_TOKEN", "kpat_secret")

    assert config.resolve_kong_mode() == "konnect"
    assert config.kong_auth_headers() == {"Authorization": "Bearer kpat_secret"}
    assert config.kong_entity_path("services") == "core-entities/services"
    assert config.kong_entity_path("routes/abc/plugins") == "core-entities/routes/abc/plugins"


def test_onprem_mode_uses_admin_token_and_bare_paths(monkeypatch):
    monkeypatch.setattr(config, "KONG_ADMIN_MODE", "onprem")
    monkeypatch.setattr(config, "KONG_ADMIN_TOKEN", "admin_secret")

    assert config.resolve_kong_mode() == "onprem"
    assert config.kong_auth_headers() == {"kong-admin-token": "admin_secret"}
    assert config.kong_entity_path("services") == "services"


@pytest.mark.parametrize("url,expected", [
    ("https://eu.api.konghq.com/v2/control-planes/abc", "konnect"),
    ("https://us.api.konghq.com/v2/control-planes/xyz", "konnect"),
    ("https://kong.internal:8444", "onprem"),
    ("https://localhost:8001", "onprem"),
])
def test_auto_mode_detects_flavour_from_url(monkeypatch, url, expected):
    monkeypatch.setattr(config, "KONG_ADMIN_MODE", "auto")
    monkeypatch.setattr(config, "KONG_ADMIN_API", url)
    assert config.resolve_kong_mode() == expected


def test_core_entities_prefix_is_not_doubled(monkeypatch):
    monkeypatch.setattr(config, "KONG_ADMIN_MODE", "konnect")
    assert config.kong_entity_path("core-entities/services") == "core-entities/services"


# --- fetch_kong_data -----------------------------------------------------------

def test_fetch_sends_correct_header_and_url(monkeypatch):
    monkeypatch.setattr(config, "KONG_ADMIN_MODE", "konnect")
    monkeypatch.setattr(config, "KONG_ADMIN_API", "https://eu.api.konghq.com/v2/control-planes/cp1")
    monkeypatch.setattr(config, "KONG_ADMIN_TOKEN", "kpat_x")
    seen = {}

    def fake_get(url, headers=None, params=None, **kwargs):
        seen["url"] = url
        seen["headers"] = headers
        return FakeResponse({"data": [{"id": "s1", "name": "svc"}]})

    monkeypatch.setattr(requests, "get", fake_get)

    data = auditor_agent.fetch_kong_data("services")
    assert data == [{"id": "s1", "name": "svc"}]
    assert seen["url"] == "https://eu.api.konghq.com/v2/control-planes/cp1/core-entities/services"
    assert seen["headers"]["Authorization"] == "Bearer kpat_x"


def test_fetch_follows_offset_pagination(monkeypatch):
    monkeypatch.setattr(config, "KONG_ADMIN_TOKEN", "t")
    monkeypatch.setattr(config, "KONG_ADMIN_API", "https://eu.api.konghq.com/v2/control-planes/cp1")
    pages = [
        {"data": [{"id": "a"}], "offset": "page2"},
        {"data": [{"id": "b"}], "offset": "page3"},
        {"data": [{"id": "c"}]},
    ]
    calls = []

    def fake_get(url, headers=None, params=None, **kwargs):
        calls.append((params or {}).get("offset"))
        return FakeResponse(pages[len(calls) - 1])

    monkeypatch.setattr(requests, "get", fake_get)

    data = auditor_agent.fetch_kong_data("services")
    assert [d["id"] for d in data] == ["a", "b", "c"]
    assert calls == [None, "page2", "page3"]


def test_fetch_raises_actionable_error_on_401(monkeypatch):
    monkeypatch.setattr(config, "KONG_ADMIN_MODE", "konnect")
    monkeypatch.setattr(config, "KONG_ADMIN_TOKEN", "bad")
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse({}, 401))

    with pytest.raises(RuntimeError, match="401 Unauthorized"):
        auditor_agent.fetch_kong_data("services")


def test_fetch_raises_actionable_error_on_404(monkeypatch):
    monkeypatch.setattr(config, "KONG_ADMIN_TOKEN", "t")
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse({}, 404))

    with pytest.raises(RuntimeError, match="control-planes"):
        auditor_agent.fetch_kong_data("services")


def test_fetch_explains_tls_interception_failure(monkeypatch):
    monkeypatch.setattr(config, "KONG_ADMIN_TOKEN", "t")

    def boom(*args, **kwargs):
        raise requests.exceptions.SSLError("certificate verify failed")

    monkeypatch.setattr(requests, "get", boom)

    with pytest.raises(RuntimeError, match="truststore"):
        auditor_agent.fetch_kong_data("services")


def test_fetch_requires_token(monkeypatch):
    monkeypatch.setattr(config, "KONG_ADMIN_TOKEN", None)
    with pytest.raises(RuntimeError, match="KONG_ADMIN_TOKEN"):
        auditor_agent.fetch_kong_data("services")


# --- inventory join ------------------------------------------------------------

SERVICES = [
    {"id": "svc-a", "name": "orders-api"},
    {"id": "svc-b", "name": "Healthcheck"},
]
ROUTES = [
    {"id": "rt-1", "service": {"id": "svc-a"}},
    {"id": "rt-2", "service": {"id": "svc-a"}},
    {"id": "rt-3", "service": {"id": "svc-b"}},
]
PLUGINS = [
    {"name": "key-auth", "route": {"id": "rt-1"}},        # route-level -> svc-a
    {"name": "rate-limiting", "service": {"id": "svc-a"}},  # service-level
    {"name": "correlation-id"},                            # global
    {"name": "acl", "consumer": {"id": "c1"}},             # consumer-only, ignored
]


@pytest.fixture
def stub_collections(monkeypatch):
    def fake_fetch(endpoint):
        if endpoint == "services":
            return SERVICES
        if endpoint == "routes":
            return ROUTES
        if endpoint == "plugins":
            return PLUGINS
        raise AssertionError(f"unexpected endpoint {endpoint}")

    monkeypatch.setattr(auditor_agent, "fetch_kong_data", fake_fetch)


def test_inventory_attributes_route_plugins_to_service(stub_collections):
    """Konnect estates bind most plugins at the route level; a plugin on any
    route of a service still protects that service."""
    inventory = auditor_agent.collect_kong_inventory()
    by_name = {s["service_name"]: s for s in inventory}

    assert by_name["orders-api"]["service_plugins"] == [
        "correlation-id", "key-auth", "rate-limiting",
    ]
    # Healthcheck has no bindings of its own, only the gateway-wide plugin.
    assert by_name["Healthcheck"]["service_plugins"] == ["correlation-id"]


def test_inventory_ignores_consumer_only_plugins(stub_collections):
    inventory = auditor_agent.collect_kong_inventory()
    for service in inventory:
        assert "acl" not in service["service_plugins"]


def test_inventory_reports_route_counts(stub_collections):
    inventory = auditor_agent.collect_kong_inventory()
    by_name = {s["service_name"]: s for s in inventory}
    assert by_name["orders-api"]["route_count"] == 2
    assert by_name["Healthcheck"]["route_count"] == 1


def test_inventory_filters_by_service_name(stub_collections):
    inventory = auditor_agent.collect_kong_inventory(service_names=["healthcheck"])
    assert [s["service_name"] for s in inventory] == ["Healthcheck"]


def test_inventory_includes_service_routes(stub_collections):
    inventory = auditor_agent.collect_kong_inventory()
    by_name = {s["service_name"]: s for s in inventory}
    routes = {r["id"]: r for r in by_name["orders-api"]["service_routes"]}
    assert set(routes) == {"rt-1", "rt-2"}
    assert routes["rt-1"]["plugin_names"] == ["key-auth"]
    assert routes["rt-2"]["plugin_names"] == []
    assert routes["rt-1"]["paths"] == [] and routes["rt-1"]["methods"] == []
    assert len(by_name["Healthcheck"]["service_routes"]) == 1


def test_collect_consumers_maps_fields(monkeypatch):
    def fake_fetch(endpoint):
        if endpoint == "consumers":
            return [{"id": "c1", "username": "mobile-app", "custom_id": "app1"}]
        return []

    monkeypatch.setattr(auditor_agent, "fetch_kong_data", fake_fetch)
    assert auditor_agent.collect_kong_consumers() == [
        {"id": "c1", "username": "mobile-app", "custom_id": "app1"}]


def test_inventory_uses_three_requests_regardless_of_size(monkeypatch):
    """Per-service route/plugin walks cost 1 + 2N requests; the join costs 3."""
    endpoints = []

    def fake_fetch(endpoint):
        endpoints.append(endpoint)
        return {"services": SERVICES, "routes": ROUTES, "plugins": PLUGINS}[endpoint]

    monkeypatch.setattr(auditor_agent, "fetch_kong_data", fake_fetch)

    auditor_agent.collect_kong_inventory()
    assert endpoints == ["services", "routes", "plugins"]
class RateLimitedResponse(FakeResponse):
    def __init__(self, payload, status_code=200, headers=None):
        super().__init__(payload, status_code)
        self.headers = headers or {}


def _no_sleep(monkeypatch):
    import time as _time
    waits = []
    monkeypatch.setattr(_time, "sleep", waits.append)
    monkeypatch.setattr(config, "KONG_RETRY_BACKOFF_S", 0)
    monkeypatch.setattr(config, "KONG_MAX_RETRIES", 2)
    return waits


def test_fetch_retries_transient_5xx(monkeypatch):
    monkeypatch.setattr(config, "KONG_ADMIN_TOKEN", "t")
    _no_sleep(monkeypatch)
    calls = []

    def flaky(url, headers=None, params=None, **kwargs):
        calls.append(url)
        if len(calls) < 3:
            return RateLimitedResponse({}, 503)
        return RateLimitedResponse({"data": [{"id": "s1"}]})

    monkeypatch.setattr(requests, "get", flaky)
    assert auditor_agent.fetch_kong_data("services") == [{"id": "s1"}]
    assert len(calls) == 3


def test_fetch_honors_retry_after_within_cap(monkeypatch):
    monkeypatch.setattr(config, "KONG_ADMIN_TOKEN", "t")
    monkeypatch.setattr(config, "KONG_RETRY_MAX_WAIT_S", 5)
    waits = _no_sleep(monkeypatch)
    calls = []

    def limited(url, headers=None, params=None, **kwargs):
        calls.append(url)
        if len(calls) == 1:
            return RateLimitedResponse({}, 429, {"Retry-After": "30"})
        return RateLimitedResponse({"data": []})

    monkeypatch.setattr(requests, "get", limited)
    assert auditor_agent.fetch_kong_data("services") == []
    assert waits == [5.0]  # Retry-After 30 clamped to the 5s cap


def test_fetch_gives_up_after_bounded_retries(monkeypatch):
    monkeypatch.setattr(config, "KONG_ADMIN_TOKEN", "t")
    _no_sleep(monkeypatch)
    monkeypatch.setattr(requests, "get",
                        lambda *a, **k: RateLimitedResponse({}, 429))
    with pytest.raises(RuntimeError, match="rate-limited"):
        auditor_agent.fetch_kong_data("services")


def test_fetch_retries_timeouts_but_not_tls_errors(monkeypatch):
    monkeypatch.setattr(config, "KONG_ADMIN_TOKEN", "t")
    _no_sleep(monkeypatch)
    calls = []

    def slow(url, headers=None, params=None, **kwargs):
        calls.append(url)
        if len(calls) == 1:
            raise requests.exceptions.ConnectTimeout("timed out")
        return RateLimitedResponse({"data": []})

    monkeypatch.setattr(requests, "get", slow)
    assert auditor_agent.fetch_kong_data("services") == []
    assert len(calls) == 2

    tls_calls = []

    def tls(url, headers=None, params=None, **kwargs):
        tls_calls.append(url)
        raise requests.exceptions.SSLError("bad cert")

    monkeypatch.setattr(requests, "get", tls)
    with pytest.raises(RuntimeError, match="truststore"):
        auditor_agent.fetch_kong_data("services")
    assert len(tls_calls) == 1  # configuration errors never retry


def test_discovery_is_read_only_at_http_layer(monkeypatch, stub_collections):
    def refuse(*args, **kwargs):
        raise AssertionError("discovery must not write")

    monkeypatch.setattr(requests, "post", refuse)
    monkeypatch.setattr(requests, "put", refuse)
    monkeypatch.setattr(requests, "patch", refuse)
    monkeypatch.setattr(requests, "delete", refuse)
    inventory = auditor_agent.collect_kong_inventory()
    assert len(inventory) == 2
