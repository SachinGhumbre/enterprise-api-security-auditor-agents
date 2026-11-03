"""
===============================================================================
 File Name   : common/conversations.py
 Description : Redis-backed conversation store for the AI Security Assistant.
               Each conversation is an owner-scoped hash plus a capped message
               list and a task list; a per-owner sorted set indexes history.
               Session isolation is structural: every read/write requires the
               owner's key fingerprint, and cross-owner access is reported as
               "not found" (never "forbidden") so ids are not an oracle.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import json
import time
import uuid
from datetime import datetime, timezone

from common import config

CONV_PREFIX = "conv:"
USER_INDEX_PREFIX = "conv:by_user:"


class ConversationNotFound(RuntimeError):
    """No conversation with this id for this owner (missing or not owned)."""


def _now():
    return datetime.now(timezone.utc).isoformat()


def safe_conversation_id(raw):
    """Filesystem/key-safe conversation id. User input is never trusted."""
    safe = "".join(c for c in str(raw or "")
                   if c.isalnum() or c in ("-", "_"))[:64]
    return safe or "conversation"


def _conv_key(conv_id):
    return f"{CONV_PREFIX}{conv_id}"


def _messages_key(conv_id):
    return f"{CONV_PREFIX}{conv_id}:messages"


def _tasks_key(conv_id):
    return f"{CONV_PREFIX}{conv_id}:tasks"


def _user_index_key(owner_fp):
    return f"{USER_INDEX_PREFIX}{owner_fp}"


# --- stores -------------------------------------------------------------------

class MemoryStore:
    """In-memory store with the Redis surface conversations need.

    Used by the test suite (no Redis required) and as a documented
    fallback shape. TTLs are recorded but not enforced; production uses
    RedisStore where expiry is real.
    """

    def __init__(self):
        self.hashes = {}
        self.lists = {}
        self.zsets = {}
        self.ttls = {}

    # hashes
    def hset(self, key, mapping):
        self.hashes.setdefault(key, {}).update(dict(mapping))

    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    # lists
    def rpush(self, key, value):
        self.lists.setdefault(key, []).append(value)

    def lrange(self, key, start, stop):
        items = self.lists.get(key, [])
        if stop < 0:
            stop = len(items) + stop
        return items[start:stop + 1]

    def ltrim(self, key, start, stop):
        items = self.lists.get(key, [])
        if stop < 0:
            stop = len(items) + stop
        self.lists[key] = items[start:stop + 1]

    def llen(self, key):
        return len(self.lists.get(key, []))

    # sorted sets
    def zadd(self, key, score, member):
        self.zsets.setdefault(key, {})[member] = float(score)

    def zrevrange(self, key, start, stop, withscores=False):
        ordered = sorted((self.zsets.get(key, {}) or {}).items(),
                         key=lambda item: item[1], reverse=True)
        if stop < 0:
            stop = len(ordered) + stop
        sliced = ordered[start:stop + 1]
        return sliced if withscores else [member for member, _ in sliced]

    def zrem(self, key, member):
        (self.zsets.get(key, {}) or {}).pop(member, None)

    # keys
    def expire(self, key, ttl_s):
        self.ttls[key] = int(ttl_s)

    def delete(self, *keys):
        for key in keys:
            self.hashes.pop(key, None)
            self.lists.pop(key, None)
            for members in self.zsets.values():
                members.pop(key, None)


class RedisStore:
    """Thin adapter over the shared Redis client (decode_responses=False)."""

    def __init__(self, client=None):
        self._client = client

    @property
    def _redis(self):
        if self._client is None:
            from common import vector_store
            self._client = vector_store.get_client()
        return self._client

    @staticmethod
    def _enc(value):
        if isinstance(value, bytes):
            return value
        return str(value).encode("utf-8")

    @staticmethod
    def _dec(value):
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value

    def hset(self, key, mapping):
        self._redis.hset(key, mapping={k: self._enc(v)
                                      for k, v in mapping.items()})

    def hgetall(self, key):
        raw = self._redis.hgetall(key) or {}
        return {self._dec(k): self._dec(v) for k, v in raw.items()}

    def rpush(self, key, value):
        self._redis.rpush(key, self._enc(value))

    def lrange(self, key, start, stop):
        return [self._dec(v)
                for v in self._redis.lrange(key, start, stop)]

    def ltrim(self, key, start, stop):
        self._redis.ltrim(key, start, stop)

    def llen(self, key):
        return int(self._redis.llen(key) or 0)

    def zadd(self, key, score, member):
        self._redis.zadd(key, {member: float(score)})

    def zrevrange(self, key, start, stop, withscores=False):
        raw = self._redis.zrevrange(key, start, stop, withscores=withscores)
        if not withscores:
            return [self._dec(v) for v in raw]
        return [(self._dec(member), score) for member, score in raw]

    def zrem(self, key, member):
        self._redis.zrem(key, member)

    def expire(self, key, ttl_s):
        try:
            self._redis.expire(key, int(ttl_s))
        except Exception:
            pass

    def delete(self, *keys):
        if keys:
            self._redis.delete(*keys)


_STORE = None


def get_store():
    global _STORE
    if _STORE is None:
        _STORE = RedisStore()
    return _STORE


def set_store(store):
    """Inject a store (MemoryStore in tests). Returns the previous store."""
    global _STORE
    previous, _STORE = _STORE, store
    return previous


def reset_store():
    global _STORE
    _STORE = None


# --- helpers ------------------------------------------------------------------

def _touch(store, conv_id, owner_fp, meta):
    now = _now()
    meta["updated_at"] = now
    store.hset(_conv_key(conv_id), {"updated_at": now,
                                   "message_count": meta.get("message_count", "0")})
    store.zadd(_user_index_key(owner_fp), time.time(), conv_id)
    ttl = config.ASSISTANT_CONV_TTL_S
    store.expire(_conv_key(conv_id), ttl)
    store.expire(_messages_key(conv_id), ttl)
    store.expire(_tasks_key(conv_id), ttl)


def _load_owned(store, owner_fp, conv_id):
    meta = store.hgetall(_conv_key(conv_id))
    if not meta or meta.get("owner_fp") != owner_fp:
        raise ConversationNotFound(
            f"No conversation '{conv_id}' for this session.")
    return meta


def _public_meta(meta, message_count=None):
    return {
        "conversation_id": meta.get("conversation_id", ""),
        "title": meta.get("title", "New conversation"),
        "created_at": meta.get("created_at", ""),
        "updated_at": meta.get("updated_at", ""),
        "summary": meta.get("summary", ""),
        "assessment_id": meta.get("assessment_id", "") or None,
        "message_count": (int(message_count) if message_count is not None
                          else int(meta.get("message_count", 0) or 0)),
    }


# --- API ----------------------------------------------------------------------

def create_conversation(owner_fp, title=None, assessment_id=None, store=None):
    """Create a conversation owned by `owner_fp`. Returns its public shape."""
    store = store or get_store()
    conv_id = f"conv-{uuid.uuid4().hex[:12]}"
    now = _now()
    meta = {
        "conversation_id": conv_id,
        "owner_fp": owner_fp,
        "title": (title or "New conversation")[:120],
        "created_at": now,
        "updated_at": now,
        "summary": "",
        "assessment_id": assessment_id or "",
        "message_count": "0",
    }
    store.hset(_conv_key(conv_id), meta)
    store.zadd(_user_index_key(owner_fp), time.time(), conv_id)
    ttl = config.ASSISTANT_CONV_TTL_S
    store.expire(_conv_key(conv_id), ttl)
    store.expire(_messages_key(conv_id), ttl)
    store.expire(_tasks_key(conv_id), ttl)
    return _public_meta(meta, 0)


def list_conversations(owner_fp, limit=50, store=None):
    """Newest-first conversation index for one owner only."""
    store = store or get_store()
    ids = store.zrevrange(_user_index_key(owner_fp), 0, max(1, int(limit)) - 1)
    out = []
    for conv_id in ids:
        meta = store.hgetall(_conv_key(conv_id))
        if not meta or meta.get("owner_fp") != owner_fp:
            continue
        count = store.llen(_messages_key(conv_id))
        out.append(_public_meta(meta, count))
    return out


def get_conversation(owner_fp, conv_id, include_messages=False,
                     message_limit=100, store=None):
    """One owned conversation, optionally with its most recent messages."""
    store = store or get_store()
    conv_id = safe_conversation_id(conv_id)
    meta = _load_owned(store, owner_fp, conv_id)
    body = _public_meta(meta, store.llen(_messages_key(conv_id)))
    if include_messages:
        body["messages"] = get_messages(owner_fp, conv_id,
                                        limit=message_limit, store=store)
        body["tasks"] = get_tasks(owner_fp, conv_id, store=store)
    return body


def delete_conversation(owner_fp, conv_id, store=None):
    """Delete an owned conversation. Returns True; unknown ids return False."""
    store = store or get_store()
    conv_id = safe_conversation_id(conv_id)
    try:
        _load_owned(store, owner_fp, conv_id)
    except ConversationNotFound:
        return False
    store.delete(_conv_key(conv_id), _messages_key(conv_id),
                 _tasks_key(conv_id))
    store.zrem(_user_index_key(owner_fp), conv_id)
    return True


def append_message(owner_fp, conv_id, role, content, kind="text",
                   extra=None, store=None):
    """Append one message; trims to ASSISTANT_MAX_MESSAGES. Returns it."""
    store = store or get_store()
    conv_id = safe_conversation_id(conv_id)
    meta = _load_owned(store, owner_fp, conv_id)
    if role not in ("user", "assistant", "system"):
        raise ValueError(f"role must be user|assistant|system, got {role!r}.")
    message = {
        "message_id": f"msg-{uuid.uuid4().hex[:8]}",
        "role": role,
        "kind": kind or "text",
        "content": content,
        "created_at": _now(),
    }
    if isinstance(extra, dict):
        for key in ("intent", "citations", "tool_calls", "task",
                    "assessment_id", "cards", "model", "verified"):
            if extra.get(key) is not None:
                message[key] = extra[key]
    store.rpush(_messages_key(conv_id), json.dumps(message))
    overflow = store.llen(_messages_key(conv_id)) - config.ASSISTANT_MAX_MESSAGES
    if overflow > 0:
        store.ltrim(_messages_key(conv_id), overflow, -1)
    count = store.llen(_messages_key(conv_id))
    meta["message_count"] = str(count)
    # First user message becomes the title when still the default.
    if (role == "user" and meta.get("title") in (None, "", "New conversation")
            and isinstance(content, str) and content.strip()):
        title = " ".join(content.split())[:120]
        meta["title"] = title
        store.hset(_conv_key(conv_id), {"title": title})
    _touch(store, conv_id, owner_fp, meta)
    return message


def get_messages(owner_fp, conv_id, limit=100, store=None):
    """Most recent `limit` messages, oldest first."""
    store = store or get_store()
    conv_id = safe_conversation_id(conv_id)
    _load_owned(store, owner_fp, conv_id)
    total = store.llen(_messages_key(conv_id))
    limit = max(1, int(limit or 100))
    start = max(0, total - limit)
    out = []
    for raw in store.lrange(_messages_key(conv_id), start, -1):
        try:
            loaded = json.loads(raw) if isinstance(raw, str) else {}
        except (TypeError, ValueError):
            continue
        if isinstance(loaded, dict):
            out.append(loaded)
    return out


def update_summary(owner_fp, conv_id, summary, store=None):
    store = store or get_store()
    conv_id = safe_conversation_id(conv_id)
    meta = _load_owned(store, owner_fp, conv_id)
    store.hset(_conv_key(conv_id), {"summary": summary or ""})
    _touch(store, conv_id, owner_fp, meta)
    return summary or ""


def link_assessment(owner_fp, conv_id, assessment_id, store=None):
    store = store or get_store()
    conv_id = safe_conversation_id(conv_id)
    meta = _load_owned(store, owner_fp, conv_id)
    store.hset(_conv_key(conv_id), {"assessment_id": assessment_id or ""})
    _touch(store, conv_id, owner_fp, meta)
    return assessment_id


def record_task(owner_fp, conv_id, task_id, assessment_id=None, label="",
                store=None):
    store = store or get_store()
    conv_id = safe_conversation_id(conv_id)
    meta = _load_owned(store, owner_fp, conv_id)
    entry = {"task_id": task_id, "assessment_id": assessment_id or "",
             "label": label or "", "created_at": _now()}
    store.rpush(_tasks_key(conv_id), json.dumps(entry))
    if assessment_id:
        store.hset(_conv_key(conv_id), {"assessment_id": assessment_id})
    _touch(store, conv_id, owner_fp, meta)
    return entry


def get_tasks(owner_fp, conv_id, store=None):
    store = store or get_store()
    conv_id = safe_conversation_id(conv_id)
    _load_owned(store, owner_fp, conv_id)
    out = []
    for raw in store.lrange(_tasks_key(conv_id), 0, -1):
        try:
            loaded = json.loads(raw) if isinstance(raw, str) else {}
        except (TypeError, ValueError):
            continue
        if isinstance(loaded, dict):
            out.append(loaded)
    return out


def build_context(owner_fp, conv_id, store=None):
    """Rolling context: stored summary plus the most recent N messages."""
    store = store or get_store()
    conv_id = safe_conversation_id(conv_id)
    meta = _load_owned(store, owner_fp, conv_id)
    messages = get_messages(owner_fp, conv_id,
                            limit=config.ASSISTANT_CONTEXT_MESSAGES,
                            store=store)
    return {"summary": meta.get("summary", ""),
            "messages": messages,
            "assessment_id": meta.get("assessment_id", "") or None,
            "message_count": int(meta.get("message_count", 0) or 0)}
