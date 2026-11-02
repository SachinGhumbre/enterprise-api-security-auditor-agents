"""Unit tests for deterministic verdict verification (Phase 1).

Covers plugin normalization, missing-claim checks, finding-level statuses
(verified / unverified / contradictory), the explainable confidence table,
evidence preservation, and the verify node's place in the audit graph.
No network, model, or Redis access - everything here is pure Python.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents import auditor_agent  # noqa: E402
from common import llm, router, rules, vector_store  # noqa: E402

def _routed(parsed, raw=""):
    return router.ModelResponse(provider="meta", model="muse-spark-1.3",
                                task="test", text=raw, parsed=parsed)



CHUNKS = [
    {
        "id": "embedding:chunk-1",
        "content": "Authentication Policy v1.0: services must enable jwt, oauth2 or key-auth.",
        "source": "01_authentication_policy.txt",
        "metadata": {},
        "score": 0.91,
    }
]


def finding(comply, missing):
    return {
        "policy_name": "Authentication Policy",
        "comply": comply,
        "missing_plugins": missing,
        "details": "stub",
    }


# --- normalization ------------------------------------------------------------

def test_alias_display_name_maps_to_canonical_id():
    assert rules.normalize_plugin("JWT Authentication")["canonical"] == "jwt"
    assert rules.normalize_plugin("Rate Limiting")["canonical"] == "rate-limiting"
    assert rules.normalize_plugin("IP Restriction")["canonical"] == "ip-restriction"


def test_normalization_ignores_case_and_whitespace():
    norm = rules.normalize_plugin("  Jwt Authentication ")
    assert norm["canonical"] == "jwt" and norm["known"]


def test_canonical_id_passes_through_as_known():
    norm = rules.normalize_plugin("openid-connect")
    assert (norm["canonical"], norm["known"], norm["ambiguous"]) == (
        "openid-connect", True, False)


def test_ambiguous_display_name_returns_candidates():
    norm = rules.normalize_plugin("OAuth2 / OpenID Connect")
    assert norm["ambiguous"] and norm["canonical"] is None
    assert norm["candidates"] == ["oauth2", "openid-connect"]


def test_unknown_identifier_passes_through_as_unknown():
    norm = rules.normalize_plugin("flux-capacitor")
    assert norm["canonical"] == "flux-capacitor" and not norm["known"]


# --- missing-claim checks -------------------------------------------------------

def test_absent_known_plugin_is_verified_missing():
    (claim,) = rules.verify_missing_claims(["key-auth"], ["jwt"])
    assert claim["result"] == "verified_missing"
    assert claim["canonical"] == "jwt"


def test_enabled_plugin_claim_is_contradicted():
    (claim,) = rules.verify_missing_claims(["jwt", "key-auth"], ["jwt"])
    assert claim["result"] == "contradicted"


def test_contradiction_detected_through_display_alias():
    """The LLM's 'JWT Authentication' must match the inventory's 'jwt'."""
    (claim,) = rules.verify_missing_claims(["jwt"], ["JWT Authentication"])
    assert claim["result"] == "contradicted"
    assert claim["canonical"] == "jwt"


def test_contradiction_ignores_case():
    (claim,) = rules.verify_missing_claims(["Rate-Limiting"], ["rate-limiting"])
    assert claim["result"] == "contradicted"


def test_contradiction_needs_no_known_plugin_entry():
    """A claim about an unlisted-but-enabled name is still disprovable."""
    (claim,) = rules.verify_missing_claims(["my-custom-plugin"], ["my-custom-plugin"])
    assert claim["result"] == "contradicted"


def test_ambiguous_claim_with_none_enabled_is_verified_missing():
    (claim,) = rules.verify_missing_claims(["key-auth"], ["OAuth2 / OpenID Connect"])
    assert claim["result"] == "verified_missing"
    assert claim["enabled_candidates"] == []


def test_ambiguous_claim_with_candidate_enabled_is_unverifiable():
    (claim,) = rules.verify_missing_claims(
        ["openid-connect"], ["OAuth2 / OpenID Connect"])
    assert claim["result"] == "unverified_ambiguous"
    assert claim["enabled_candidates"] == ["openid-connect"]


def test_unknown_plugin_claim_is_flagged_not_guessed():
    (claim,) = rules.verify_missing_claims(["key-auth"], ["PII Sanitizer (AI Plugin)"])
    assert claim["result"] == "unknown_plugin"


# --- finding-level status -------------------------------------------------------

def test_compliant_finding_with_nothing_missing_is_verified():
    record = rules.verify_policy_finding(
        finding(True, []), ["jwt"], CHUNKS, ["OWASP API Top 10"])
    assert record["status"] == "verified"
    assert record["confidence"] == "high"


def test_compliant_finding_listing_missing_is_contradictory():
    record = rules.verify_policy_finding(finding(True, ["jwt"]), ["key-auth"], CHUNKS)
    assert record["status"] == "contradictory"
    assert record["confidence"] == "low"
    assert record["notes"]


def test_non_compliant_finding_without_named_plugin_is_unverified():
    """Missing evidence must surface as unverified, never as proof."""
    record = rules.verify_policy_finding(finding(False, []), ["key-auth"], CHUNKS)
    assert record["status"] == "unverified"
    assert record["confidence"] == "low"


def test_verified_grounded_finding_has_high_confidence():
    record = rules.verify_policy_finding(
        finding(False, ["jwt"]), ["key-auth"], CHUNKS, ["GDPR"])
    assert (record["status"], record["confidence"]) == ("verified", "high")
    assert record["evidence"]["grounded"] is True
    assert record["evidence"]["chunk_ids"] == ["embedding:chunk-1"]
    assert record["evidence"]["sources"] == ["01_authentication_policy.txt"]
    assert record["evidence"]["standards_in_scope"] == ["GDPR"]


def test_verified_ungrounded_finding_has_medium_confidence():
    """Inventory absence is still a fact with no chunks; the requirement is not."""
    record = rules.verify_policy_finding(finding(False, ["jwt"]), ["key-auth"], [])
    assert (record["status"], record["confidence"]) == ("verified", "medium")
    assert "no policy excerpt" in record["confidence_basis"]
    assert record["evidence"]["grounded"] is False


def test_contradicted_claim_makes_finding_contradictory():
    record = rules.verify_policy_finding(
        finding(False, ["jwt", "key-auth"]), ["key-auth"], CHUNKS)
    assert record["status"] == "contradictory"
    results = {c["result"] for c in record["claims"]}
    assert results == {"verified_missing", "contradicted"}


def test_unknown_claim_makes_finding_unverified():
    record = rules.verify_policy_finding(
        finding(False, ["flux-capacitor"]), ["key-auth"], CHUNKS)
    assert (record["status"], record["confidence"]) == ("unverified", "low")


def test_malformed_finding_degrades_to_unverified():
    record = rules.verify_policy_finding("not-a-dict", ["key-auth"], CHUNKS)
    assert record["status"] == "unverified"


# --- evidence preservation ------------------------------------------------------

def test_evidence_preserves_ids_sources_and_scores():
    evidence = rules.build_service_evidence(CHUNKS)
    assert evidence["grounded"] is True
    assert evidence["chunk_count"] == 1
    chunk = evidence["chunks"][0]
    assert (chunk["id"], chunk["source"], chunk["score"]) == (
        "embedding:chunk-1", "01_authentication_policy.txt", 0.91)
    assert chunk["truncated"] is False


def test_evidence_truncates_long_excerpts_transparently():
    long_chunk = dict(CHUNKS[0], content="x" * 2000)
    (chunk,) = rules.build_service_evidence([long_chunk])["chunks"]
    assert chunk["truncated"] is True
    assert len(chunk["excerpt"]) == rules.MAX_EXCERPT_CHARS


def test_empty_evidence_is_explicitly_ungrounded():
    evidence = rules.build_service_evidence([])
    assert evidence == {"grounded": False, "chunk_count": 0, "chunks": []}


def test_summarize_counts_statuses_and_legacy_policies():
    report = {
        "a": {"policies": [{"verification": {"status": "verified"}}]},
        "b": {"policies": [{"verification": {"status": "contradictory"}}]},
        "c": {"policies": [{"policy_name": "legacy, no verification key"}]},
        "d": {"error": "boom", "policies": []},
    }
    assert rules.summarize_verification(report) == {
        "verified": 1, "unverified": 2, "contradictory": 1}


# --- verify node and graph wiring -------------------------------------------------

def test_verify_node_attaches_evidence_and_status():
    state = auditor_agent.verify_audit({
        "selected_standards": ["OWASP API Top 10"],
        "policy_context": {"Svc": CHUNKS},
        "audit_report": {
            "Svc:policy:Svc": {
                "serviceName": "Svc",
                "service_plugins": ["key-auth"],
                "policies": [finding(False, ["jwt"])],
            }
        },
    })
    entry = state["audit_report"]["Svc:policy:Svc"]
    assert entry["policy_evidence"]["grounded"] is True
    assert entry["policies"][0]["verification"]["status"] == "verified"
    assert entry["verification_summary"]["status"] == "verified"
    assert state["verification_counts"] == {
        "verified": 1, "unverified": 0, "contradictory": 0}


def test_verify_node_marks_error_entries_unverified():
    state = auditor_agent.verify_audit({
        "audit_report": {
            "Svc:policy:Svc": {
                "serviceName": "Svc",
                "service_plugins": [],
                "policies": [],
                "error": "Audit call failed",
            }
        },
    })
    entry = state["audit_report"]["Svc:policy:Svc"]
    assert entry["verification_summary"]["status"] == "unverified"
    assert state["verification_counts"]["unverified"] == 1


def test_graph_runs_verify_between_reason_and_plan(monkeypatch, tmp_path):
    """End-to-end: one verified and one contradictory finding, summary persisted."""
    audit_json = {
        "serviceName": "Svc",
        "policies": [
            finding(False, ["jwt"]),
            finding(False, ["key-auth"]),
        ],
    }
    monkeypatch.setattr(router, "run",
                        lambda *a, **k: _routed(audit_json, json.dumps(audit_json)))
    monkeypatch.setattr(vector_store, "ping", lambda: True)
    monkeypatch.setattr(vector_store, "index_exists", lambda *a, **k: True)
    monkeypatch.setattr(vector_store, "search", lambda query, top_k=5, **k: CHUNKS)
    monkeypatch.setattr(auditor_agent, "AUDIT_REPORT_FILE",
                        str(tmp_path / "langgraph_audit_report.json"))
    monkeypatch.setattr(auditor_agent, "AUDIT_SUMMARY_FILE",
                        str(tmp_path / "langgraph_audit_summary.json"))

    result = auditor_agent.audit_app.invoke({
        "kong_data": [{"service_name": "Svc", "service_id": "s1",
                       "service_plugins": ["key-auth"]}],
        "selected_standards": ["OWASP API Top 10"],
    })

    entry = result["audit_report"]["Svc:policy:Svc"]
    assert [p["verification"]["status"] for p in entry["policies"]] == [
        "verified", "contradictory"]
    assert result["summary"]["verification"] == {
        "verified": 1, "unverified": 0, "contradictory": 1}

    with open(auditor_agent.AUDIT_SUMMARY_FILE, encoding="utf-8") as handle:
        saved = json.load(handle)
    assert saved["summary"]["verification"]["contradictory"] == 1
    assert saved["provenance"]["provider"] == llm.provider()
    assert saved["provenance"]["model"] == llm.model_name()
    assert saved["provenance"]["timestamp"]
    assert saved["provenance"]["kong_source"] == "request"

    # The report artifact keeps its bare-dict contract for existing consumers.
    with open(auditor_agent.AUDIT_REPORT_FILE, encoding="utf-8") as handle:
        assert set(json.load(handle)) == {"Svc:policy:Svc"}
