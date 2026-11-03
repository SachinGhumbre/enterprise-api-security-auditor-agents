"""Tests for the start_all.py service launcher (helpers only; no real
subprocesses or sockets are opened)."""

import os
import sys
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(sys.path[0]))

import start_all  # noqa: E402


def test_plan_order_and_defaults(monkeypatch, tmp_path):
    monkeypatch.setattr(start_all, "ROOT", str(tmp_path))
    plan = start_all.services_to_run()
    assert [s["key"] for s in plan] == ["redis-test", "knowledge",
                                        "agents", "frontend"]
    assert [s["port"] for s in plan[:3]] == [5002, 5001, 5000]
    assert plan[0]["script"] == "redis-test.py"
    assert plan[2]["script"].endswith("init_auditor.py")
    assert plan[3]["npm"] is True


def test_plan_skips(monkeypatch, tmp_path):
    monkeypatch.setattr(start_all, "ROOT", str(tmp_path))
    plan = start_all.services_to_run(skip_redis_test=True, skip_frontend=True)
    assert [s["key"] for s in plan] == ["knowledge", "agents"]


def test_plan_honours_env_ports(monkeypatch, tmp_path):
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / ".env").write_text("AGENTS_PORT = 5009\n# comment\n"
                                  "KNOWLEDGE_PORT=5019\n")
    monkeypatch.setattr(start_all, "ROOT", str(tmp_path))
    plan = start_all.services_to_run(skip_frontend=True)
    by_key = {s["key"]: s for s in plan}
    assert by_key["agents"]["port"] == 5009
    assert by_key["knowledge"]["port"] == 5019
    assert by_key["redis-test"]["port"] == 5002  # hardcoded upstream


def test_is_serving_counts_http_errors_as_up(monkeypatch):
    def boom(url, timeout=3):
        raise urllib.error.HTTPError(url, 503, "degraded", {}, None)

    monkeypatch.setattr(start_all.urllib.request, "urlopen", boom)
    assert start_all.is_serving("http://localhost:5000/x") is True

    def refused(url, timeout=3):
        raise urllib.error.URLError("refused")

    monkeypatch.setattr(start_all.urllib.request, "urlopen", refused)
    assert start_all.is_serving("http://localhost:5000/x") is False


class _Proc:
    def __init__(self, codes):
        self.codes = list(codes)
        self.returncode = None

    def poll(self):
        if self.codes:
            self.returncode = self.codes.pop(0)
        return self.returncode


def test_wait_for_health_success(monkeypatch):
    calls = []

    def fake_serving(url, timeout=3):
        calls.append(url)
        return len(calls) >= 2

    monkeypatch.setattr(start_all, "is_serving", fake_serving)
    monkeypatch.setattr(start_all.time, "sleep", lambda s: None)
    ok, _ = start_all.wait_for_health(_Proc([None, None]), "http://x", 30)
    assert ok is True and len(calls) == 2


def test_wait_for_health_detects_early_exit(monkeypatch):
    monkeypatch.setattr(start_all, "is_serving", lambda *a, **k: False)
    monkeypatch.setattr(start_all.time, "sleep", lambda s: None)
    ok, detail = start_all.wait_for_health(_Proc([None, 1]), "http://x", 30)
    assert ok is False and "code 1" in detail


def test_wait_for_health_times_out(monkeypatch):
    monkeypatch.setattr(start_all, "is_serving", lambda *a, **k: False)
    monkeypatch.setattr(start_all.time, "sleep", lambda s: None)
    ok, detail = start_all.wait_for_health(_Proc([None] * 1000), "http://x",
                                           0)
    assert ok is False and "no HTTP response" in detail


def test_preflight_missing_npm(monkeypatch):
    monkeypatch.setattr(start_all.shutil, "which", lambda name: None)
    assert "npm was not found" in start_all.preflight(want_frontend=True)
    assert start_all.preflight(want_frontend=False) == ""


def test_preflight_missing_python_dep(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "flask":
            raise ImportError("no flask")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert "flask" in start_all.preflight(want_frontend=False)


def test_main_skips_running_services(monkeypatch, tmp_path):
    def interrupted(_seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(start_all, "ROOT", str(tmp_path))
    monkeypatch.setattr(start_all, "port_occupied", lambda *a, **k: True)
    monkeypatch.setattr(start_all, "is_serving", lambda *a, **k: True)
    monkeypatch.setattr(start_all, "preflight", lambda **k: "")
    monkeypatch.setattr(start_all.time, "sleep", interrupted)
    launched = []
    monkeypatch.setattr(start_all.subprocess, "Popen",
                        lambda *a, **k: launched.append(a))
    assert start_all.main(["--skip-frontend"]) == start_all.EXIT_OK
    assert launched == []


def test_main_launches_free_ports_without_slow_probe(monkeypatch, tmp_path):
    def interrupted(_seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(start_all, "ROOT", str(tmp_path))
    monkeypatch.setattr(start_all, "port_occupied", lambda *a, **k: False)
    probed = []
    monkeypatch.setattr(start_all, "is_serving",
                        lambda *a, **k: probed.append(a) or False)
    monkeypatch.setattr(start_all, "preflight", lambda **k: "")
    monkeypatch.setattr(start_all, "wait_for_health",
                        lambda *a, **k: (True, "healthy"))
    monkeypatch.setattr(start_all.time, "sleep", interrupted)
    launched = []
    monkeypatch.setattr(start_all, "launch_python",
                        lambda script: launched.append(script) or _Proc([None]))
    assert start_all.main(["--skip-frontend",
                           "--skip-redis-test"]) == start_all.EXIT_OK
    assert [s.replace("\\", "/") for s in launched] == [
        "backend/rag/knowledge_ingestor.py", "backend/agents/init_auditor.py"]
    assert probed == []


def test_port_occupied_branches(monkeypatch):
    """Hermetic: scripted bind outcomes, no real sockets."""
    import errno
    import socket as stdlib_socket

    scripted = []
    addresses = []
    created = []

    class FakeSocket:
        def __init__(self, *args, **kwargs):
            created.append(self)
            self.closed = False

        def bind(self, address):
            addresses.append(address)
            outcome = scripted.pop(0)
            if outcome is not None:
                raise outcome

        def close(self):
            self.closed = True

    monkeypatch.setattr(stdlib_socket, "socket", FakeSocket)

    scripted.append(None)  # bind succeeds -> port is free
    assert start_all.port_occupied(5000) is False

    scripted.append(OSError(errno.EADDRINUSE, "in use"))  # held port
    assert start_all.port_occupied(5000) is True

    assert addresses == [("127.0.0.1", 5000)] * 2
    assert created and all(sock.closed for sock in created)


def test_main_refuses_duplicate_on_hung_port(monkeypatch, tmp_path):
    monkeypatch.setattr(start_all, "ROOT", str(tmp_path))
    monkeypatch.setattr(start_all, "is_serving", lambda *a, **k: False)
    monkeypatch.setattr(start_all, "port_occupied", lambda *a, **k: True)
    monkeypatch.setattr(start_all, "preflight", lambda **k: "")
    launched = []
    monkeypatch.setattr(start_all, "launch_python",
                        lambda script: launched.append(script))
    assert start_all.main(["--skip-frontend", "--skip-redis-test"]) == \
        start_all.EXIT_FAILED
    assert launched == []


def test_main_fails_when_health_never_passes(monkeypatch, tmp_path):
    monkeypatch.setattr(start_all, "ROOT", str(tmp_path))
    monkeypatch.setattr(start_all, "is_serving", lambda *a, **k: False)
    monkeypatch.setattr(start_all, "port_occupied", lambda *a, **k: False)
    monkeypatch.setattr(start_all, "preflight", lambda **k: "")
    monkeypatch.setattr(start_all, "wait_for_health",
                        lambda *a, **k: (False, "nope"))
    monkeypatch.setattr(start_all, "launch_python",
                        lambda script: _Proc([None]))
    stopped = []
    monkeypatch.setattr(start_all, "stop_all",
                        lambda procs: stopped.extend(procs))
    assert start_all.main(["--skip-frontend", "--skip-redis-test"]) == \
        start_all.EXIT_FAILED
    assert [name for name, _ in stopped] == ["knowledge"]
