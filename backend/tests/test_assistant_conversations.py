"""Tests for the assistant conversation store: CRUD, isolation, caps."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import conversations  # noqa: E402


@pytest.fixture
def store():
    memory = conversations.MemoryStore()
    previous = conversations.set_store(memory)
    try:
        yield memory
    finally:
        conversations.set_store(previous)


def test_create_and_get_conversation(store):
    body = conversations.create_conversation("fp-a", assessment_id="asm-1")
    assert body["conversation_id"].startswith("conv-")
    assert body["title"] == "New conversation"
    assert body["assessment_id"] == "asm-1"
    assert body["message_count"] == 0

    fetched = conversations.get_conversation(
        "fp-a", body["conversation_id"], include_messages=True)
    assert fetched["conversation_id"] == body["conversation_id"]
    assert fetched["messages"] == []
    assert fetched["tasks"] == []


def test_session_isolation_between_owners(store):
    body = conversations.create_conversation("fp-a")
    conversations.append_message("fp-a", body["conversation_id"],
                                 "user", "secret finding")
    # Another owner sees nothing: not found, never forbidden (no oracle).
    with pytest.raises(conversations.ConversationNotFound):
        conversations.get_conversation("fp-b", body["conversation_id"])
    with pytest.raises(conversations.ConversationNotFound):
        conversations.get_messages("fp-b", body["conversation_id"])
    with pytest.raises(conversations.ConversationNotFound):
        conversations.append_message("fp-b", body["conversation_id"],
                                     "user", "hi")
    assert conversations.delete_conversation(
        "fp-b", body["conversation_id"]) is False
    assert conversations.list_conversations("fp-b") == []
    # The owner is unaffected.
    assert len(conversations.get_messages(
        "fp-a", body["conversation_id"])) == 1


def test_unknown_conversation_is_not_found(store):
    with pytest.raises(conversations.ConversationNotFound):
        conversations.get_conversation("fp-a", "conv-missing")


def test_first_user_message_becomes_title(store):
    body = conversations.create_conversation("fp-a")
    conversations.append_message("fp-a", body["conversation_id"],
                                 "user", "  Why is SvcB non-compliant?  ")
    fetched = conversations.get_conversation("fp-a", body["conversation_id"])
    assert fetched["title"] == "Why is SvcB non-compliant?"
    assert fetched["message_count"] == 1


def test_message_history_is_capped(store, monkeypatch):
    from common import config
    monkeypatch.setattr(config, "ASSISTANT_MAX_MESSAGES", 5)
    body = conversations.create_conversation("fp-a")
    for index in range(8):
        conversations.append_message("fp-a", body["conversation_id"],
                                     "user", f"m{index}")
    messages = conversations.get_messages("fp-a", body["conversation_id"])
    assert [m["content"] for m in messages] == [f"m{i}" for i in range(3, 8)]
    fetched = conversations.get_conversation("fp-a", body["conversation_id"])
    assert fetched["message_count"] == 5


def test_message_roles_are_validated(store):
    body = conversations.create_conversation("fp-a")
    with pytest.raises(ValueError, match="role must be"):
        conversations.append_message("fp-a", body["conversation_id"],
                                     "robot", "beep")


def test_tasks_and_assessment_link(store):
    body = conversations.create_conversation("fp-a")
    conversations.record_task("fp-a", body["conversation_id"], "task-1",
                              assessment_id="asm-9", label="assessment")
    tasks = conversations.get_tasks("fp-a", body["conversation_id"])
    assert tasks[0]["task_id"] == "task-1"
    assert tasks[0]["assessment_id"] == "asm-9"
    fetched = conversations.get_conversation("fp-a", body["conversation_id"])
    assert fetched["assessment_id"] == "asm-9"
    conversations.link_assessment("fp-a", body["conversation_id"], "asm-10")
    assert conversations.get_conversation(
        "fp-a", body["conversation_id"])["assessment_id"] == "asm-10"


def test_build_context_returns_summary_plus_recent(store, monkeypatch):
    from common import config
    monkeypatch.setattr(config, "ASSISTANT_CONTEXT_MESSAGES", 3)
    body = conversations.create_conversation("fp-a")
    conversations.update_summary("fp-a", body["conversation_id"], "prior work")
    for index in range(5):
        conversations.append_message("fp-a", body["conversation_id"],
                                     "user", f"m{index}")
    context = conversations.build_context("fp-a", body["conversation_id"])
    assert context["summary"] == "prior work"
    assert [m["content"] for m in context["messages"]] == ["m2", "m3", "m4"]
    assert context["message_count"] == 5


def test_delete_removes_history(store):
    body = conversations.create_conversation("fp-a")
    conversations.append_message("fp-a", body["conversation_id"],
                                 "user", "hi")
    assert conversations.delete_conversation(
        "fp-a", body["conversation_id"]) is True
    assert conversations.list_conversations("fp-a") == []
    with pytest.raises(conversations.ConversationNotFound):
        conversations.get_conversation("fp-a", body["conversation_id"])


def test_conversation_ids_are_sanitized(store):
    body = conversations.create_conversation("fp-a")
    with pytest.raises(conversations.ConversationNotFound):
        conversations.get_conversation("fp-a", "../../etc/passwd")
