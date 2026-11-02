"""Unit tests for the versioned policy assessment engine."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import policy  # noqa: E402


def _evidence(plugins=(), routes=(), chunks=()):
    return {"service_name": "Svc", "service_id": "s1",
            "plugins": list(plugins), "routes": list(routes),
            "chunks": list(chunks)}


def _chunk(chunk_id, content):
    return {"id": chunk_id, "content": content, "source": "s.txt",
            "metadata": {}, "score": 0.9}


def _control(control_id):
    return next(c for c in policy.CONTROLS if c.id == control_id)


# --- catalog ---------------------------------------------------------------------

def test_catalog_is_versioned_and_complete():
    assert policy.CATALOG_VERSION == "1.0.0"
    assert len(policy.CONTROLS) == 27
    ids = [c.id for c in policy.CONTROLS]
    assert len(set(ids)) == len(ids)
    for control in policy.CONTROLS:
        assert control.version and control.severity in policy.SEVERITIES
        assert control.standards and control.source_doc
        assert control.check in policy.CHECKS
        assert control.action and control.validation


def test_catalog_covers_all_policy_groups():
    domains = {c.domain for c in policy.CONTROLS}
    assert {"owasp", "isms", "authentication", "authorisation", "privacy",
            "encryption", "rate_limiting", "logging", "exposure"} <= domains


# --- checks ------------------------------------------------------------------------

def test_strong_auth_outcomes():
    assert policy.evaluate_control(_control("AUTH-01"),
                                   _evidence(["jwt"]))["outcome"] == "satisfied"
    assert policy.evaluate_control(_control("AUTH-01"),
                                   _evidence(["key-auth"]))["outcome"] == "partial"
    assert policy.evaluate_control(_control("AUTH-01"),
                                   _evidence([]))["outcome"] == "unsatisfied"


def test_plugin_presence_checks():
    assert policy.evaluate_control(_control("RL-01"),
                                   _evidence(["rate-limiting"]))["outcome"] == "satisfied"
    assert policy.evaluate_control(_control("RL-01"),
                                   _evidence([]))["outcome"] == "unsatisfied"
    assert policy.evaluate_control(_control("LOG-01"),
                                   _evidence(["syslog"]))["outcome"] == "satisfied"
    assert policy.evaluate_control(_control("OWASP-API9"),
                                   _evidence([], [{"path": "/"}]))["outcome"] == "satisfied"
    assert policy.evaluate_control(_control("OWASP-API9"),
                                   _evidence([]))["outcome"] == "unsatisfied"


def test_insufficient_evidence_yields_not_evaluable_with_reason():
    result = policy.evaluate_control(_control("TLS-01"), _evidence(["jwt"]))
    assert result["outcome"] == "not_evaluable"
    assert "route protocols" in result["reason"]
    for control_id in ("OWASP-API1", "OWASP-API5", "GDPR-32", "EXP-02", "EXP-03"):
        assert policy.evaluate_control(_control(control_id),
                                       _evidence())["outcome"] == "not_evaluable"


def test_unknown_check_fails_open_as_not_evaluable():
    bad = policy.Control(id="X", domain="d", title="t", version="1.0",
                         severity="Low", standards=["S"], source_doc="s",
                         check="nope")
    result = policy.evaluate_control(bad, _evidence())
    assert result["outcome"] == "not_evaluable"
    assert "no verdict claimed" in result["reason"]


# --- grounding and provenance ------------------------------------------------------------

def test_grounding_matches_keywords_to_chunks():
    control = _control("OWASP-API2")
    grounded, chunk_ids = policy.grounding(
        control, _evidence(chunks=[_chunk("c1", "services must enable jwt")]))
    assert grounded is True and chunk_ids == ["c1"]
    grounded, chunk_ids = policy.grounding(
        control, _evidence(chunks=[_chunk("c2", "unrelated prose")]))
    assert grounded is False and chunk_ids == []


def test_control_result_preserves_provenance():
    result = policy.evaluate_control(
        _control("AUTH-01"),
        _evidence(["key-auth"], chunks=[_chunk("c1", "enable jwt please")]))
    assert result["catalog_version"] == "1.0.0"
    assert result["version"] == "1.0"
    assert result["source_doc"] == "01_authentication_policy.txt"
    assert result["chunk_ids"] == ["c1"]


# --- coverage -------------------------------------------------------------------------------

def test_coverage_counts_and_gaps():
    results = {
        "Svc": [
            {"control_id": "A", "domain": "owasp", "title": "t",
             "outcome": "satisfied", "severity": "High", "reason": ""},
            {"control_id": "B", "domain": "owasp", "title": "t",
             "outcome": "unsatisfied", "severity": "High", "reason": "r"},
            {"control_id": "C", "domain": "privacy", "title": "t",
             "outcome": "not_evaluable", "severity": "Low", "reason": "needs X"},
        ]
    }
    coverage = policy.compute_coverage(results)
    assert coverage["totals"] == {"total": 3, "satisfied": 1, "partial": 0,
                                  "unsatisfied": 1, "not_evaluable": 1}
    assert coverage["by_domain"]["owasp"]["unsatisfied"] == 1
    assert [(g["control_id"], g["outcome"]) for g in coverage["gaps"]] == [
        ("B", "unsatisfied"), ("C", "not_evaluable")]


# --- finding schema ------------------------------------------------------------------------------

def _finding_fields(**overrides):
    fields = {
        "finding_id": "F-1",
        "affected_api": {"api": "Svc",
                         "gateway_resource": {"kind": "service", "name": "Svc",
                                              "id": "s1"}},
        "category": "owasp", "severity": "High", "confidence": "medium",
        "evidence": [],
        "applicable_standard": {"standard": "OWASP",
                                "control": "OWASP-API4 v1.0",
                                "catalog_version": "1.0.0"},
        "business_impact": "i", "attack_scenario": "s",
        "recommended_action": "a", "validation_method": "inventory",
        "assessed_at": "2026-01-01T00:00:00+00:00",
        "evidence_freshness": {"retrieved_at": "", "age_s": 1, "stale": False},
    }
    fields.update(overrides)
    return fields


def test_finding_schema_has_thirteen_fields():
    finding = policy.build_finding(**_finding_fields())
    assert len(finding) == 13
    assert set(finding) == set(policy.FINDING_REQUIRED)


def test_finding_rejects_missing_fields_and_bad_enums():
    fields = _finding_fields()
    del fields["severity"]
    with pytest.raises(ValueError, match="severity"):
        policy.build_finding(**fields)
    with pytest.raises(ValueError, match="severity"):
        policy.build_finding(**_finding_fields(severity="Extreme"))
    with pytest.raises(ValueError, match="confidence"):
        policy.build_finding(**_finding_fields(confidence="certain"))


def test_freshness_marks_stale_and_unparseable():
    fresh = policy.freshness("2026-01-01T00:00:00+00:00",
                             "2026-01-01T01:00:00+00:00")
    assert fresh["stale"] is False and fresh["age_s"] == 3600.0
    stale = policy.freshness("2026-01-01T00:00:00+00:00",
                             "2026-01-03T00:00:00+00:00")
    assert stale["stale"] is True
    broken = policy.freshness("not-a-time")
    assert broken["stale"] is True and broken["age_s"] is None


def test_control_result_to_finding_mapping():
    service = {"service_name": "Svc", "service_id": "s1"}
    assert policy.control_result_to_finding(
        {"outcome": "satisfied"}, service, "F", None) is None
    assert policy.control_result_to_finding(
        {"outcome": "not_evaluable"}, service, "F", None) is None

    unsatisfied = {
        "outcome": "unsatisfied", "domain": "owasp", "severity": "High",
        "control_id": "OWASP-API4", "version": "1.0",
        "catalog_version": "1.0.0", "standards": ["OWASP"],
        "source_doc": "03_rate_limiting.txt", "reason": "not enabled",
        "grounded": True, "chunk_ids": ["c1"],
    }
    finding = policy.control_result_to_finding(
        unsatisfied, service, "F-1", "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:10+00:00")
    assert finding["confidence"] == "high"
    assert finding["tier"] == "suspected"
    assert finding["affected_api"]["api"] == "Svc"
    assert finding["affected_api"]["gateway_resource"]["id"] == "s1"
    assert finding["applicable_standard"]["control"] == "OWASP-API4 v1.0"
    assert len(finding["evidence"]) == 2  # inventory + excerpt
    assert finding["evidence_freshness"]["stale"] is False

    partial = dict(unsatisfied, outcome="partial", grounded=False, chunk_ids=[])
    assert policy.control_result_to_finding(
        partial, service, "F-2", None)["confidence"] == "low"
