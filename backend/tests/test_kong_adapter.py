"""Tests for the restricted Kong write adapter and the fix simulator."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import changes, config, kong_adapter  # noqa: E402

INVENTORY = [
    {"service_name": "SvcB", "service_id": "b",
     "service_plugins": [], "service_routes": []},
]

PROSE = {"rationale": "jwt is required by policy.",
         "preconditions": ["maintenance window agreed"],
         "consumer_impact": "clients must send JWTs.",
         "breaking_changes": ["unauthenticated calls will fail"],
         "validation_plan": ["call health endpoint with JWT"]}


def _finding():
    return {"finding_id": "F-1", "service": "SvcB",
            "policy_name": "Authentication Policy", "comply": False,
            "missing_plugins": ["jwt"], "details": "jwt missing."}


def _approved():
    proposal, error = changes.build_proposal(_finding(), INVENTORY, ["SvcB"])
    assert error is None
    changes.attach_proposal_prose(proposal, PROSE)
    changes.approve(proposal, "sec-lead")
    return proposal


def test_unapproved_change_cannot_execute(monkeypatch):
    monkeypatch.setattr(config, "KONG_WRITE_ENABLED", True)
    calls = []
    proposal, _ = changes.build_proposal(_finding(), INVENTORY, ["SvcB"])
    changes.attach_proposal_prose(proposal, PROSE)
    with pytest.raises(kong_adapter.KongNotApproved):
        kong_adapter.execute(
            proposal, ["SvcB"],
            http=lambda *a: calls.append(a) or (201, {"id": "p1"}))
    assert calls == []  # no gateway call was attempted
    assert proposal["status"] == "failed"
    assert "KongNotApproved" in proposal["execution"]["error"]


def test_live_execution_requires_write_flag(monkeypatch):
    monkeypatch.setattr(config, "KONG_WRITE_ENABLED", False)
    with pytest.raises(kong_adapter.KongWritesDisabled):
        kong_adapter.execute(_approved(), ["SvcB"],
                             http=lambda *a: (201, {"id": "p1"}))


def test_out_of_scope_and_invalid_are_refused(monkeypatch):
    monkeypatch.setattr(config, "KONG_WRITE_ENABLED", True)
    with pytest.raises(kong_adapter.KongOutOfScope):
        kong_adapter.execute(_approved(), ["Other"],
                             http=lambda *a: (201, {"id": "p1"}))
    bad = _approved()
    bad["op"] = "delete_service"
    with pytest.raises(kong_adapter.KongInvalid, match="allowlisted"):
        kong_adapter.execute(bad, ["SvcB"], http=lambda *a: (201, {}))


def test_successful_execution_is_validated_and_recorded(monkeypatch):
    monkeypatch.setattr(config, "KONG_WRITE_ENABLED", True)
    monkeypatch.setattr(config, "KONG_ADMIN_API", "https://kong.test")
    calls = []

    def fake_http(method, url, headers, payload):
        calls.append((method, url, payload))
        if method == "POST":
            assert url.endswith("/plugins") and payload["name"] == "jwt"
            return 201, {"id": "p1", "name": "jwt"}
        assert url.endswith("/plugins/p1")
        return 200, {"id": "p1", "name": "jwt"}

    proposal = kong_adapter.execute(_approved(), ["SvcB"], http=fake_http)
    assert proposal["status"] == "validated"
    execution = proposal["execution"]
    assert execution["approver"] == "sec-lead"
    assert execution["mode"] == "live" and execution["error"] is None
    assert execution["started_at"] and execution["finished_at"]
    assert execution["ops"] == [{"op": "enable_plugin", "http_status": 201,
                                 "plugin_id": "p1"}]
    assert proposal["post_validation"]["passed"] is True
    assert len(proposal["post_validation"]["checks"]) == 2
    assert [c[0] for c in calls] == ["POST", "GET"]


def test_failed_change_is_reported_accurately(monkeypatch):
    monkeypatch.setattr(config, "KONG_WRITE_ENABLED", True)
    monkeypatch.setattr(config, "KONG_ADMIN_API", "https://kong.test")

    def failing(method, url, headers, payload):
        return 500, {"message": "boom"}

    proposal = _approved()
    with pytest.raises(kong_adapter.KongOpFailed, match="HTTP 500"):
        kong_adapter.execute(proposal, ["SvcB"], http=failing)
    assert proposal["status"] == "failed"
    assert "HTTP 500" in proposal["execution"]["error"]
    assert proposal["execution"]["ops"] == []
    assert proposal["post_validation"] is None


def test_failed_readback_leaves_change_unvalidated(monkeypatch):
    monkeypatch.setattr(config, "KONG_WRITE_ENABLED", True)
    monkeypatch.setattr(config, "KONG_ADMIN_API", "https://kong.test")

    def fake_http(method, url, headers, payload):
        if method == "POST":
            return 201, {"id": "p1", "name": "jwt"}
        return 404, {}

    proposal = kong_adapter.execute(_approved(), ["SvcB"], http=fake_http)
    assert proposal["status"] == "executed"  # not validated
    assert proposal["post_validation"]["passed"] is False


def test_rollback_is_gated_and_scoped(monkeypatch):
    monkeypatch.setattr(config, "KONG_WRITE_ENABLED", True)
    monkeypatch.setattr(config, "KONG_ADMIN_API", "https://kong.test")
    rollback = _approved()
    rollback.update({"op": "remove_plugin",
                     "rollback_of": {"change_id": rollback["change_id"],
                                     "plugin_id": "p1"}})
    with pytest.raises(kong_adapter.KongInvalid, match="rollback-only"):
        kong_adapter.execute(rollback, ["SvcB"],
                             http=lambda *a: (204, {}))
    calls = []
    rollback["status"] = "approved"  # reset the recorded refusal
    rollback["execution"] = None
    done = kong_adapter.execute(
        rollback, ["SvcB"], allow_rollback=True,
        http=lambda m, u, h, p: calls.append((m, u)) or (204, {}))
    assert done["status"] == "validated"
    assert calls == [("DELETE", "https://kong.test/plugins/p1")]


def test_suspicious_plugin_id_is_refused(monkeypatch):
    monkeypatch.setattr(config, "KONG_WRITE_ENABLED", True)
    monkeypatch.setattr(config, "KONG_ADMIN_API", "https://kong.test")
    rollback = _approved()
    rollback.update({"op": "remove_plugin",
                     "rollback_of": {"change_id": "x",
                                     "plugin_id": "../services"}})
    with pytest.raises(kong_adapter.KongAdapterError):
        kong_adapter.execute(rollback, ["SvcB"], allow_rollback=True,
                             http=lambda *a: (204, {}))


def test_simulator_shows_effect_without_writes():
    proposal = _approved()
    entry = {"entry_id": "R-1", "service": "SvcB",
             "severity": "High", "confidence": "high"}
    report = kong_adapter.simulate(proposal, INVENTORY, entry)
    assert report["ok"] is True and report["mode"] == "simulate"
    assert report["effect"] == "jwt enabled on SvcB"
    assert report["residual_risk"]["after"] < report["residual_risk"]["before"]
    assert INVENTORY[0]["service_plugins"] == []  # untouched
    assert "no live gateway resources" in report["note"]
    assert proposal["simulation"] is report
