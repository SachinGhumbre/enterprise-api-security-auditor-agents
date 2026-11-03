"""Tests for the root-level Redis test harness (redis-test.py).

index_info backs the Overview dashboard card, which abandons the probe after
30s (frontend health.redisTest timeout). These tests pin the two properties
that keep that card alive on a slow/stalled link to Redis: bounded socket
timeouts on the client, and a single FT.INFO round trip per probe.
"""

import importlib.util
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HARNESS_PATH = os.path.join(ROOT, "redis-test.py")


@pytest.fixture(scope="module")
def harness():
    # The file name has a hyphen, so it cannot be imported normally.
    spec = importlib.util.spec_from_file_location("redis_harness", HARNESS_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _FakeFT:
    def __init__(self, info=None, error=None):
        self._info = info
        self._error = error
        self.info_calls = 0

    def info(self):
        self.info_calls += 1
        if self._error is not None:
            raise self._error
        return self._info


class _FakeHarnessRedis:
    """Stands in for redis.Redis with decode_responses=False (bytes replies)."""

    def __init__(self, info=None, error=None, keys=()):
        self._ft = _FakeFT(info, error)
        self._keys = list(keys)
        self.scan_calls = 0

    def ft(self, name):
        assert name
        return self._ft

    def scan_iter(self, match=None, count=None):
        self.scan_calls += 1
        return iter(self._keys)


def test_redis_client_attempts_fit_dashboard_probe(harness):
    kwargs = harness.redis_client.connection_pool.connection_kwargs
    connect = kwargs.get("socket_connect_timeout")
    command = kwargs.get("socket_timeout")
    retry = kwargs.get("retry")
    assert connect is not None, "harness client must bound connection setup"
    assert command is not None, "harness client must bound each command"
    # redis-py's Retry takes `retries` retries after the first attempt, and
    # TimeoutError is in the retried set: attempts = retries + 1, each able
    # to burn a full connect + command timeout on a stalled link.
    attempts = retry._retries + 1 if retry is not None else 1
    # Worst case for index_info, every attempt stalled: one connect + a single
    # FT.INFO (no key sweep — see below) must answer well inside the
    # dashboard's 30s probe budget (frontend health.redisTest timeout).
    assert attempts * (connect + command) * 1 < 30


def test_index_info_single_probe_round_trip(harness, monkeypatch):
    fake = _FakeHarnessRedis(
        info={b"num_docs": b"12", b"index_name": b"security_auditor_index"},
        keys=[b"embedding:1", b"embedding:2"],
    )
    monkeypatch.setattr(harness, "redis_client", fake)
    resp = harness.app.test_client().get("/redis/index_info")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["exists"] is True
    assert body["num_docs"] == 12
    assert "stored_keys" not in body
    assert fake._ft.info_calls == 1
    # No full-keyspace sweep on the probe path: each SCAN page is another
    # stalled-link multiplier. Key inventory lives in /redis/all_embeddings.
    assert fake.scan_calls == 0


def test_index_info_missing_index_still_200(harness, monkeypatch):
    fake = _FakeHarnessRedis(error=Exception("Unknown index name"), keys=[])
    monkeypatch.setattr(harness, "redis_client", fake)
    resp = harness.app.test_client().get("/redis/index_info")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["exists"] is False
    assert body["num_docs"] == 0
    assert fake._ft.info_calls == 1
    assert fake.scan_calls == 0
