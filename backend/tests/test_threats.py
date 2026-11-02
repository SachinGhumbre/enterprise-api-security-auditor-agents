"""Unit tests for the deterministic threat-scenario engine."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import threats  # noqa: E402


def _service(name, plugins=(), routes=()):
    return {"service_name": name, "service_id": f"id-{name}",
            "service_plugins": list(plugins),
            "service_routes": list(routes)}


def _route(name, paths, methods=(), plugins=()):
    return {"id": f"rt-{name}", "name": name, "paths": list(paths),
            "methods": list(methods), "plugin_names": list(plugins)}


SHOP = _service(
    "shop-api", [],
    [_route("get-user", ["/api/v1/users/{id}"], ["GET"]),
     _route("create-order", ["/api/v1/orders"], ["POST"])])

HARDENED = _service(
    "vault-api", ["jwt", "acl", "rate-limiting", "request-validator",
                  "http-log", "response-transformer"],
    [_route("health", ["/api/v1/health"], ["GET"], ["jwt"])])


def _ids(scenarios):
    return sorted(s["scenario_id"] for s in scenarios)


def test_route_signals_detect_paths_methods_and_auth():
    signals = threats.route_signals(SHOP)
    assert signals["id_param_routes"] == ["get-user"]
    assert signals["sensitive_routes"] == ["get-user", "create-order"]
    assert signals["state_changing_routes"] == ["create-order"]
    assert signals["unauthenticated_routes"] == ["get-user", "create-order"]
    assert signals["service_auth"] == []


def test_exposed_api_fires_expected_scenarios():
    ids = _ids(threats.detect_scenarios(SHOP))
    assert {"bola", "broken_auth", "bopla", "consumption",
            "excessive_exposure"} <= set(ids)
    assert "inventory" not in ids  # routes exist


def test_hardened_api_fires_nothing():
    assert threats.detect_scenarios(HARDENED) == []


def test_bfla_needs_sensitive_routes_without_acl():
    admin = _service("admin-api", ["key-auth"],
                     [_route("admin-users", ["/admin/users"], ["GET"])])
    assert "bfla" in _ids(threats.detect_scenarios(admin))
    guarded = _service("admin-api", ["key-auth", "acl"],
                       [_route("admin-users", ["/admin/users"], ["GET"])])
    assert "bfla" not in _ids(threats.detect_scenarios(guarded))


def test_debug_routes_flag_misconfiguration():
    svc = _service("ops-api", ["jwt", "rate-limiting"],
                   [_route("debug", ["/internal/debug"], ["GET"])])
    assert "misconfig" in _ids(threats.detect_scenarios(svc))


def test_routeless_service_flags_inventory():
    assert "inventory" in _ids(threats.detect_scenarios(_service("ghost-api")))


def test_priority_service_escalates_sensitive_ops():
    pay = _service("pay-api", [],
                   [_route("pay", ["/api/v1/payment"], ["POST"])])
    plain = {s["scenario_id"]: s for s in threats.detect_scenarios(pay)}
    assert plain["sensitive_ops_abuse"]["severity_hint"] == "High"
    urgent = {s["scenario_id"]: s
              for s in threats.detect_scenarios(pay, ["pay-api"])}
    assert urgent["sensitive_ops_abuse"]["severity_hint"] == "Critical"


def test_all_scenarios_are_hypotheses_with_safe_tests():
    for scenario in threats.detect_scenarios(SHOP):
        assert scenario["hypothesis"] is True
        assert scenario["preconditions"] and scenario["evidence_refs"]
        assert scenario["recommended_tests"]
        assert all(t.startswith("Authorized testing only: ")
                   for t in scenario["recommended_tests"])


def test_unsafe_consumption_is_an_assessment_limitation():
    assert threats.unsafe_consumption_limitation([]) is None
    limitation = threats.unsafe_consumption_limitation([SHOP])
    assert limitation["scenario_id"] == "unsafe_consumption"
    assert limitation["hypothesis"] is True


def test_related_services_need_shared_evidence():
    left = _service("a-api", ["jwt"],
                    [_route("r", ["/api/v1/things"], ["GET"])])
    right = _service("b-api", ["jwt"],
                     [_route("r", ["/api/v1/other"], ["GET"])])
    unrelated = _service("c-api", ["key-auth"],
                         [_route("r", ["/v9/else"], ["GET"])])
    relations = threats.related_services([left, right, unrelated])
    assert len(relations) == 1
    assert relations[0]["services"] == ["a-api", "b-api"]
    assert "shared_auth:jwt" in relations[0]["via"]
    assert "shared_path_prefix:/api/v1" in relations[0]["via"]
