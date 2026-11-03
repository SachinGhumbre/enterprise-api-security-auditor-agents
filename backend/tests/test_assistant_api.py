"""HTTP tests for the assistant API: conversations, turns, tasks, isolation."""

import json
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents import assistant, tools  # noqa: E402
from common import conversations  # noqa: E402


@pytest.fixture
def store(monkeypatch):
    memory = conversations.MemoryStore()
    monkeypatch.setattr(conversations, "_STORE", memory)
    from common import audit_log
    monkeypatch.setattr(audit_log, "record", lambda *a, **k: {})
    return memory


@pytest.fixture
def client():
    from agents.init_auditor import app as flask_app
    flask_app.config.update(TESTING=True)
    return flask_app.test_client()


def _stub_search(monkeypatch, chunks=()):
    monkeypatch.setitem(
        tools.TOOL_DEFS, "assistant_search_policies",
        {"fn": (lambda _r=list(chunks), **k: _r), "uses_llm": False})


def _router_text(monkeypatch, text="stubbed copilot reply"):
    from common import router
    fake = types.SimpleNamespace(text=text, model="muse-spark-1.3",
                                 parsed=None)
    monkeypatch.setattr(router, "run", lambda *a, **k: fake)


def _sse_events(response):
    events = []
    for frame in response.get_data(as_text=True).split("\n\n"):
        for line in frame.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                events.append(json.loads(line[5:].strip()))
    return events


def test_prompts_endpoint_lists_demo_starters(client):
    body = client.get("/api/v1/ai-agents/assistant/prompts").get_json()
    assert any("Audit all APIs" in p for p in body["prompts"])


def test_conversation_crud_round_trip(client, store):
    created = client.post("/api/v1/ai-agents/assistant/conversations",
                          json={"title": "Q3 review"})
    assert created.status_code == 201
    conv_id = created.get_json()["conversation_id"]

    listed = client.get("/api/v1/ai-agents/assistant/conversations")
    assert [c["conversation_id"] for c in
            listed.get_json()["conversations"]] == [conv_id]

    fetched = client.get(
        f"/api/v1/ai-agents/assistant/conversations/{conv_id}")
    assert fetched.status_code == 200
    assert fetched.get_json()["messages"] == []

    deleted = client.delete(
        f"/api/v1/ai-agents/assistant/conversations/{conv_id}")
    assert deleted.status_code == 200
    assert client.get(
        f"/api/v1/ai-agents/assistant/conversations/{conv_id}").status_code == 404


def test_unknown_conversation_is_404(client, store):
    assert client.get(
        "/api/v1/ai-agents/assistant/conversations/conv-nope").status_code == 404
    assert client.post(
        "/api/v1/ai-agents/assistant/conversations/conv-nope/messages",
        json={"message": "hi"}).status_code == 404


def test_message_validation(client, store):
    created = client.post("/api/v1/ai-agents/assistant/conversations",
                          json={}).get_json()
    conv_id = created["conversation_id"]
    assert client.post(
        f"/api/v1/ai-agents/assistant/conversations/{conv_id}/messages",
        json={}).status_code == 400
    assert client.post(
        f"/api/v1/ai-agents/assistant/conversations/{conv_id}/messages",
        json={"message": "   "}).status_code == 400
    assert client.post(
        f"/api/v1/ai-agents/assistant/conversations/{conv_id}/messages",
        json={"message": "x" * 5000}).status_code == 400


def test_sync_turn_end_to_end(client, store, monkeypatch):
    _stub_search(monkeypatch, [{
        "id": "embedding:1", "content": "jwt is required.",
        "source": "01_authentication_policy.txt",
        "metadata": {"policy_version": "1.0"}, "score": 0.9}])
    _router_text(monkeypatch)
    conv_id = client.post(
        "/api/v1/ai-agents/assistant/conversations", json={}).get_json()[
            "conversation_id"]
    response = client.post(
        f"/api/v1/ai-agents/assistant/conversations/{conv_id}/messages",
        json={"message": "Explain authentication requirements"})
    assert response.status_code == 200
    body = response.get_json()
    assert body["intent"] == "knowledge"
    assert body["message"]["content"] == "stubbed copilot reply"
    assert body["citations"][0]["ref"] == \
        "source:01_authentication_policy.txt"
    thread = client.get(
        f"/api/v1/ai-agents/assistant/conversations/{conv_id}").get_json()
    assert [m["role"] for m in thread["messages"]] == ["user", "assistant"]


def test_stream_turn_emits_header_deltas_done(client, store, monkeypatch):
    from common import router
    _stub_search(monkeypatch, [{
        "id": "embedding:1", "content": "jwt is required.",
        "source": "01_authentication_policy.txt",
        "metadata": {}, "score": 0.9}])

    def fake_stream(self, task, messages, max_tokens=None, route=None):
        yield {"delta": "streamed "}
        yield {"delta": "reply"}
        yield {"response": {"model": "muse-spark-1.3"}}

    monkeypatch.setattr(router.Router, "run_stream", fake_stream)
    conv_id = client.post(
        "/api/v1/ai-agents/assistant/conversations", json={}).get_json()[
            "conversation_id"]
    response = client.post(
        f"/api/v1/ai-agents/assistant/conversations/{conv_id}/messages/stream",
        json={"message": "Explain authentication requirements"})
    assert response.status_code == 200
    assert response.mimetype == "text/event-stream"
    events = _sse_events(response)
    assert events[0]["type"] == "header"
    assert events[0]["intent"] == "knowledge"
    assert [e["delta"] for e in events if "delta" in e] == ["streamed ",
                                                            "reply"]
    assert events[-1]["type"] == "done"
    assert events[-1]["message"]["content"] == "streamed reply"
    thread = client.get(
        f"/api/v1/ai-agents/assistant/conversations/{conv_id}").get_json()
    assert len(thread["messages"]) == 2


def test_stream_unknown_conversation_is_404(client, store):
    assert client.post(
        "/api/v1/ai-agents/assistant/conversations/conv-nope/messages/stream",
        json={"message": "hi"}).status_code == 404


def test_task_status_unknown_is_404(client):
    assert client.get(
        "/api/v1/ai-agents/assistant/tasks/task-nope").status_code == 404


def test_task_status_reports_seeded_task(client, monkeypatch):
    tools._ASSISTANT_TASKS["task-seeded"] = {
        "task_id": "task-seeded", "assessment_id": "asm-missing",
        "status": "running"}
    try:
        response = client.get("/api/v1/ai-agents/assistant/tasks/task-seeded")
        assert response.status_code == 200
        assert response.get_json()["task_id"] == "task-seeded"
    finally:
        tools._ASSISTANT_TASKS.pop("task-seeded", None)


def test_conversations_are_isolated_per_key(client, store, monkeypatch):
    from common import config
    monkeypatch.setattr(config, "ADMIN_API_KEYS", [])
    monkeypatch.setattr(config, "OPERATOR_API_KEYS", [])
    monkeypatch.setattr(config, "VIEWER_API_KEYS", ["view-1", "view-2"])

    created = client.post(
        "/api/v1/ai-agents/assistant/conversations", json={},
        headers={"X-API-Key": "view-1"})
    assert created.status_code == 201
    conv_id = created.get_json()["conversation_id"]

    # The other key sees neither the conversation nor its history.
    assert client.get(
        f"/api/v1/ai-agents/assistant/conversations/{conv_id}",
        headers={"X-API-Key": "view-2"}).status_code == 404
    other = client.get("/api/v1/ai-agents/assistant/conversations",
                       headers={"X-API-Key": "view-2"}).get_json()
    assert other["conversations"] == []
    own = client.get("/api/v1/ai-agents/assistant/conversations",
                     headers={"X-API-Key": "view-1"}).get_json()
    assert [c["conversation_id"] for c in
            own["conversations"]] == [conv_id]


def test_viewer_chat_allowed_but_operator_intent_rejected(client, store,
                                                          monkeypatch):
    from common import config
    monkeypatch.setattr(config, "ADMIN_API_KEYS", [])
    monkeypatch.setattr(config, "OPERATOR_API_KEYS", ["op-1"])
    monkeypatch.setattr(config, "VIEWER_API_KEYS", ["view-1"])
    _router_text(monkeypatch)
    conv_id = client.post(
        "/api/v1/ai-agents/assistant/conversations", json={},
        headers={"X-API-Key": "view-1"}).get_json()["conversation_id"]
    denied = client.post(
        f"/api/v1/ai-agents/assistant/conversations/{conv_id}/messages",
        json={"message": "Audit all APIs and identify critical issues"},
        headers={"X-API-Key": "view-1"})
    assert denied.status_code == 200  # guard passes; the graph refuses
    assert "operator" in denied.get_json()["message"]["content"]
    assert denied.get_json()["task"] is None


def test_operator_can_start_assessment_from_chat(client, store, monkeypatch):
    from common import config
    monkeypatch.setattr(config, "ADMIN_API_KEYS", [])
    monkeypatch.setattr(config, "OPERATOR_API_KEYS", ["op-1"])
    monkeypatch.setattr(config, "VIEWER_API_KEYS", ["view-1"])
    monkeypatch.setitem(
        tools.TOOL_DEFS, "assistant_start_assessment",
        {"fn": lambda **k: {"task_id": "task-7",
                            "assessment_id": "asm-7", "status": "running"},
         "uses_llm": False})
    _router_text(monkeypatch)
    conv_id = client.post(
        "/api/v1/ai-agents/assistant/conversations", json={},
        headers={"X-API-Key": "op-1"}).get_json()["conversation_id"]
    started = client.post(
        f"/api/v1/ai-agents/assistant/conversations/{conv_id}/messages",
        json={"message": "Audit all APIs and identify critical issues"},
        headers={"X-API-Key": "op-1"})
    assert started.status_code == 200
    assert started.get_json()["task"]["task_id"] == "task-7"


def test_unauthenticated_chat_is_rejected_when_enabled(client, monkeypatch):
    from common import config
    monkeypatch.setattr(config, "ADMIN_API_KEYS", ["adm-1"])
    monkeypatch.setattr(config, "OPERATOR_API_KEYS", [])
    monkeypatch.setattr(config, "VIEWER_API_KEYS", [])
    assert client.post(
        "/api/v1/ai-agents/assistant/conversations",
        json={}).status_code == 401
