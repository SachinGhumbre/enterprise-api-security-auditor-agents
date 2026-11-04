"""Unit tests for the enterprise risk register engine."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import risks  # noqa: E402


def _llm(fid, service="shop-api", missing=("jwt",), severity="High",
         confidence="high", tier="suspected"):
    return {"finding_id": fid, "service": service, "comply": False,
            "policy_name": "Authentication Policy",
            "missing_plugins": list(missing), "details": "d",
            "service_plugins": ["key-auth"], "evidence_ids": ["c1"],
            "severity": severity, "tier": tier,
            "verification": {"status": "verified", "confidence": confidence}}


def _policy(fid, service="shop-api", control="OWASP-API2 v1.0",
            severity="Critical", confidence="high"):
    return {"finding_id": fid,
            "affected_api": {"api": service},
            "category": "owasp", "severity": severity, "confidence": confidence,
            "evidence": [{"kind": "inventory", "ref": "service:shop-api",
                          "detail": "r"}],
            "applicable_standard": {"standard": "OWASP", "control": control,
                                    "catalog_version": "1.0.0"},
            "tier": "suspected"}


def _lookup(priority=False):
    return {"shop-api": {"service_plugins": [], "service_routes": [
        {"paths": ["/api/v1/users"], "methods": ["GET"]},
        {"paths": ["/api/v1/orders"], "methods": ["POST"]}],
        "_priority": priority}}


def test_duplicates_merge_into_one_entry():
    entries = risks.build_register(
        [_llm("F-1", missing=("jwt",)), _llm("F-2", missing=("JWT",))],
        [], _lookup())
    assert len(entries) == 1
    assert sorted(s["finding_id"] for s in entries[0]["sources"]) == ["F-1", "F-2"]


def test_cross_stream_duplicates_merge():
    entries = risks.build_register([_llm("F-1")], [_policy("P-1")], _lookup())
    assert len(entries) == 1
    assert sorted(s["stream"] for s in entries[0]["sources"]) == ["llm", "policy"]
    assert entries[0]["severity"] == "Critical"  # max wins
    assert entries[0]["severity_conflicts"]


def test_scoring_formula_is_documented_math():
    entry = {"severity": "Critical", "confidence": "high"}
    factors = risks.score_factors("shop-api", _lookup(priority=True), entry)
    score, level = risks.score_entry(factors)
    # base = .3*10 + .2*9 + .15*8 + .15*8 + .2*9 = 9.0; blend .92
    assert score == 8.3
    assert level == "Critical"


def test_scoring_config_is_configurable():
    entry = {"severity": "Low", "confidence": "high"}
    factors = risks.score_factors("shop-api", _lookup(), entry)
    default, _ = risks.score_entry(factors)
    custom = risks.RiskScoringConfig.from_dict(
        {"weights": {"severity": 1.0, "exploitability": 0.0, "exposure": 0.0,
                      "sensitivity": 0.0, "criticality": 0.0}})
    tuned, _ = risks.score_entry(factors, custom)
    assert tuned != default
    assert tuned == round(2.5 * 0.92, 1)


def test_missing_business_context_uses_stated_defaults():
    factors = risks.score_factors("ghost-api", {}, {"severity": "High",
                                                    "confidence": "medium"})
    assert factors["criticality"] == {
        "score": 4.0, "rationale": "not listed as priority; assumed standard"}
    assert "unlabelled" in factors["sensitivity"]["rationale"]


def test_confidence_modulates_without_changing_severity():
    lookup = _lookup(priority=True)
    high = risks.score_entry(risks.score_factors(
        "shop-api", lookup, {"severity": "Critical", "confidence": "high"}))
    low = risks.score_entry(risks.score_factors(
        "shop-api", lookup, {"severity": "Critical", "confidence": "low"}))
    assert high[0] > low[0]
    entries = risks.build_register(
        [_llm("F-1", severity="Critical", confidence="low")], [], lookup)
    assert entries[0]["severity"] == "Critical"  # severity untouched
    assert entries[0]["confidence"] == "low"


def test_unverified_findings_never_become_verified():
    entries = risks.build_register(
        [_llm("F-1", severity="Critical", confidence="low",
              tier="unverified")],
        [], _lookup())
    assert entries[0]["verified"] is False
    assert entries[0]["tier"] == "unverified"


def test_confirmed_tier_verifies_entry():
    entries = risks.build_register(
        [_llm("F-1", tier="confirmed")], [], _lookup())
    assert entries[0]["verified"] is True
    assert entries[0]["tier"] == "confirmed"


def test_lifecycle_transitions():
    entry = {"state": "open", "state_history": []}
    risks.transition(entry, "accepted", actor="ciso", note="risk accepted")
    assert entry["state"] == "accepted"
    assert entry["state_history"][0]["actor"] == "ciso"
    risks.transition(entry, "remediated")
    assert entry["state"] == "remediated"
    with pytest.raises(ValueError, match="Invalid transition"):
        risks.transition(entry, "accepted")


def test_scoring_version_is_recorded():
    entries = risks.build_register([_llm("F-1")], [], _lookup())
    assert entries[0]["scoring_model"] == risks.SCORING_MODEL_VERSION
    assert entries[0]["formula"] == risks.SCORING_FORMULA


def test_capability_correlation_and_control_links():
    llm = [_llm("F-1", service="shop-api"), _llm("F-2", service="shop-admin")]
    controls = [{"service": "shop-api", "control_id": "OWASP-API2"},
                {"service": "shop-api", "control_id": "RL-01"}]
    entries = risks.build_register(llm, [], _lookup(), controls)
    by_id = {e["entry_id"]: e for e in entries}
    assert by_id["R-shop-api-authentication"]["correlated_entries"] == [
        "R-shop-admin-authentication"]
    assert by_id["R-shop-api-authentication"]["linked_controls"] == ["OWASP-API2"]

def test_merge_group_tolerates_null_severity_and_confidence():
    """Explicit nulls (LLM emitted `"severity": null`) must not crash the
    conflict sort when merged with a labelled finding."""
    nulls = _llm("f1", severity=None, confidence=None)
    labelled = _llm("f2", severity="High", confidence="high")
    entry = risks.merge_group(("shop-api", "authentication"),
                              [("llm", nulls), ("llm", labelled)])
    assert entry["severity"] == "High"
    assert entry["confidence"] == "high"
