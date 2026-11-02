"""Unit tests for the controlled remediation change engine."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import changes  # noqa: E402

INVENTORY = [
    {"service_name": "SvcA", "service_id": "a",
     "service_plugins": ["key-auth", "rate-limiting"], "service_routes": []},
    {"service_name": "SvcB", "service_id": "b",
     "service_plugins": [], "service_routes": []},
]

PROSE = {"rationale": "jwt is required by policy.",
         "preconditions": ["maintenance window agreed"],
         "consumer_impact": "clients must send JWTs.",
         "breaking_changes": ["unauthenticated calls will fail"],
         "validation_plan": ["call health endpoint with JWT"]}


def _finding(**overrides):
    base = {"finding_id": "F-1", "service": "SvcB",
            "policy_name": "Authentication Policy", "comply": False,
            "missing_plugins": ["jwt"], "details": "jwt missing."}
    base.update(overrides)
    return base


def _proposal(**overrides):
    proposal, error = changes.build_proposal(
        _finding(), INVENTORY, ["SvcA", "SvcB"], assessment_id="asm-1")
    assert error is None
    changes.attach_proposal_prose(proposal, PROSE)
    proposal.update(overrides)
    return proposal


def test_build_proposal_derives_exact_target():
    proposal, error = changes.build_proposal(
        _finding(), INVENTORY, ["SvcB"], assessment_id="asm-1")
    assert error is None
    assert proposal["change_id"] == "CH-svcb-enable_plugin-jwt"
    assert proposal["target"] == {"kind": "service", "service": "SvcB"}
    assert proposal["plugin"] == "jwt"
    assert proposal["current"]["found"] is True
    assert proposal["diff"][0]["added"] == ["jwt"]
    assert proposal["rollback"]["op"] == "remove_plugin"


def test_build_proposal_rejects_inexact_targets():
    _, error = changes.build_proposal(
        _finding(service=None), INVENTORY, ["SvcB"])
    assert "no affected service" in error
    _, error = changes.build_proposal(
        _finding(missing_plugins=["jwt", "oauth2"]), INVENTORY, ["SvcB"])
    assert "exactly one" in error
    _, error = changes.build_proposal(
        _finding(missing_plugins=["not-a-plugin"]), INVENTORY, ["SvcB"])
    assert "not a known Kong plugin" in error
    _, error = changes.build_proposal(
        _finding(service="Ghost"), INVENTORY, ["Ghost"])
    assert "not in retrieved inventory" in error
    _, error = changes.build_proposal(
        _finding(service="SvcA", missing_plugins=["key-auth"]),
        INVENTORY, ["SvcA"])
    assert "already enabled" in error


def test_build_proposal_maps_policy_controls_to_plugins():
    finding = {"finding_id": "P-1",
               "affected_api": {"api": "SvcB"},
               "applicable_standard": {"control": "OWASP-API2 v1.0"}}
    proposal, error = changes.build_proposal(finding, INVENTORY, ["SvcB"])
    assert error is None
    assert proposal["plugin"] == "jwt"


def test_attach_prose_rejects_smuggled_keys():
    proposal, _ = changes.build_proposal(_finding(), INVENTORY, ["SvcB"])
    with pytest.raises(ValueError, match="unexpected prose keys"):
        changes.attach_proposal_prose(
            proposal, {**PROSE, "patch": {"config": {"x": 1}}})
    with pytest.raises(ValueError, match="non-empty string"):
        changes.attach_proposal_prose(proposal, {**PROSE, "rationale": " "})
    with pytest.raises(ValueError, match="non-empty list"):
        changes.attach_proposal_prose(proposal, {**PROSE, "preconditions": []})


def test_validate_accepts_complete_proposal():
    ok, reasons = changes.validate_proposal(_proposal(), ["SvcA", "SvcB"])
    assert ok, reasons


def test_validate_rejects_unsafe_proposals():
    ok, reasons = changes.validate_proposal(
        _proposal(op="delete_service"), ["SvcA", "SvcB"])
    assert not ok and any("allowlisted" in r for r in reasons)
    ok, reasons = changes.validate_proposal(_proposal(), ["SvcA"])
    assert not ok and any("outside the assessment scope" in r
                          for r in reasons)
    ok, reasons = changes.validate_proposal(
        _proposal(patch={"config": {"minute": 1}}), ["SvcA", "SvcB"])
    assert not ok and any("default config" in r for r in reasons)
    ok, reasons = changes.validate_proposal(
        _proposal(rationale=""), ["SvcA", "SvcB"])
    assert not ok and any("rationale" in r for r in reasons)


def test_simulate_applies_to_copy_only():
    proposal = _proposal()
    updated, report = changes.simulate_apply(INVENTORY, proposal)
    assert report["ok"] is True
    assert INVENTORY[1]["service_plugins"] == []  # untouched
    svc = next(s for s in updated if s["service_name"] == "SvcB")
    assert svc["service_plugins"] == ["jwt"]
    _, repeat = changes.simulate_apply(updated, proposal)
    assert repeat["ok"] is False and "already enabled" in repeat["error"]
    _, missing = changes.simulate_apply([], proposal)
    assert missing["ok"] is False and "missing" in missing["error"]


def test_residual_risk_rescores_entry():
    entry = {"entry_id": "R-1", "service": "SvcB",
             "severity": "High", "confidence": "high"}
    result = changes.residual_risk(
        entry, {"service_plugins": []}, {"service_plugins": ["jwt"]})
    assert result == {"before": 5.3, "level_before": "Medium",
                      "after": 4.2, "level_after": "Medium"}
    assert changes.residual_risk({}, {}, {})["error"]


def test_approve_records_reviewer():
    proposal = _proposal()
    changes.approve(proposal, "sec-lead", note="window agreed")
    assert proposal["status"] == "approved"
    assert proposal["approvals"][0]["reviewer"] == "sec-lead"
    with pytest.raises(ValueError, match="reviewer is required"):
        changes.approve(_proposal(), "  ")
    with pytest.raises(ValueError, match="not 'proposed'"):
        changes.approve(proposal, "other")


def test_execution_and_validation_marks():
    proposal = _proposal()
    changes.mark_executed(proposal, {"error": "boom"})
    assert proposal["status"] == "failed"
    proposal = _proposal()
    changes.mark_executed(proposal, {"ops": ["enable_plugin jwt"]})
    assert proposal["status"] == "executed"
    changes.mark_validated(proposal, {"passed": False})
    assert proposal["status"] == "executed"  # failed checks don't validate
    changes.mark_validated(proposal, {"passed": True})
    assert proposal["status"] == "validated"
