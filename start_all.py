#!/usr/bin/env python3
"""
===============================================================================
 File Name   : start_all.py
 Description : One-command launcher for the full Enterprise API Security
               Auditor stack, in dependency order:

                 1. redis-test.py (Redis harness, :5002, optional)
                 2. backend/rag/knowledge_ingestor.py (knowledge API, :5001)
                 3. backend/agents/init_auditor.py (agents API, :5000)
                 4. frontend (npm start, :3000)

               Each Python service is started only after the previous one
               answers its health endpoint (or is already running, in which
               case it is skipped). Agents/knowledge ports come from
               backend/.env when set, else the documented defaults; the
               Redis harness listens on a fixed 5002.

               Run from the repo root with the backend venv activated:

                   .\\backend\\.venv\\Scripts\\Activate.ps1
                   python start_all.py

               On Windows every service opens in its own console window and
               keeps running after this launcher exits. On other platforms
               the launcher supervises the children until Ctrl+C.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import argparse
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_PREFLIGHT = 2

# (service key, script or None for npm, env port key, default port, health path)
SERVICE_SPECS = (
    ("redis-test", "redis-test.py", None, 5002, "/redis/index_info"),
    ("knowledge", os.path.join("backend", "rag", "knowledge_ingestor.py"),
     "KNOWLEDGE_PORT", 5001, "/api/v1/knowledge/health"),
    ("agents", os.path.join("backend", "agents", "init_auditor.py"),
     "AGENTS_PORT", 5000, "/api/v1/ai-agents/health"),
)


def parse_env_ports(env_path):
    """Read *_PORT overrides from backend/.env without third-party deps."""
    ports = {}
    try:
        with open(env_path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, _, value = line.partition("=")
                name, value = name.strip(), value.strip().strip("'\"")
                if name.endswith("_PORT") and value.isdigit():
                    ports[name] = int(value)
    except OSError:
        pass
    return ports


def service_port(env_ports, env_key, default):
    if env_key is not None and env_key in env_ports:
        return env_ports[env_key]
    return default


def services_to_run(skip_redis_test=False, skip_frontend=False):
    """Ordered service plan. Each entry has key/script/port/health/npm."""
    env_ports = parse_env_ports(os.path.join(ROOT, "backend", ".env"))
    plan = []
    for key, script, env_key, default_port, health_path in SERVICE_SPECS:
        if key == "redis-test" and skip_redis_test:
            continue
        plan.append({
            "key": key,
            "script": script,
            "port": service_port(env_ports, env_key, default_port),
            "health": health_path,
            "npm": False,
        })
    if not skip_frontend:
        plan.append({"key": "frontend", "script": None, "port": 3000,
                     "health": None, "npm": True})
    return plan


def is_serving(url, timeout=3):
    """True when something answers HTTP (any status, even 4xx/5xx)."""
    try:
        urllib.request.urlopen(url, timeout=timeout)
        return True
    except urllib.error.HTTPError:
        return True  # an HTTP status proves a server is listening
    except Exception:
        return False


def port_occupied(port):
    """True when a TCP listener (healthy or hung) holds localhost:port.

    Bind-based: a free port accepts a bind, a held one raises OSError
    (EADDRINUSE). A connect-based probe cannot tell the two apart on
    hosts whose firewall drops refused loopback connections, where
    connecting to a free port times out exactly like a hung listener.
    """
    import socket
    probe = socket.socket()
    try:
        # No SO_REUSEADDR: the bind must fail if anything holds the port,
        # whether on loopback or a wildcard address.
        probe.bind(("127.0.0.1", port))
        return False
    except OSError:
        return True  # held, or otherwise not available to take
    finally:
        probe.close()


def wait_for_health(proc, url, timeout_s, poll_s=2):
    """Wait until `url` answers or `proc` dies. Returns (ok, detail)."""
    deadline = time.time() + max(1, timeout_s)
    while time.time() < deadline:
        if proc.poll() is not None:
            return False, f"process exited with code {proc.returncode}"
        if is_serving(url):
            return True, "healthy"
        time.sleep(poll_s)
    return False, f"no HTTP response within {timeout_s}s"


def preflight(want_frontend=True):
    """Fail fast with actionable hints. Returns an error string or ''."""
    if want_frontend and shutil.which("npm") is None:
        return ("npm was not found on PATH; install Node.js 18+ or rerun "
                "with --skip-frontend.")
    missing = []
    for module in ("flask", "redis"):
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    if missing:
        return (f"Python is missing {', '.join(missing)}; activate the "
                "backend venv and run "
                "`python -m pip install -r backend/requirements.txt`.")
    if sys.version_info < (3, 11):
        print("warning: Python 3.11+ is required; "
              f"running {sys.version.split()[0]}", flush=True)
    return ""


def launch_python(script):
    path = os.path.join(ROOT, script)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"service script not found: {path}")
    kwargs = {"cwd": ROOT}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_CONSOLE
    return subprocess.Popen([sys.executable, path], **kwargs)


def launch_frontend():
    directory = os.path.join(ROOT, "frontend")
    if not os.path.isfile(os.path.join(directory, "package.json")):
        raise FileNotFoundError(f"frontend project not found: {directory}")
    kwargs = {"cwd": directory}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_CONSOLE
        # npm is a .cmd shim on Windows; it needs a shell.
        return subprocess.Popen("npm start", shell=True, **kwargs)
    return subprocess.Popen(["npm", "start"], **kwargs)


def stop_all(processes):
    """Terminate launched children (best effort, process-tree aware)."""
    for name, proc in processes:
        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    check=False)
            else:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except Exception as exc:
            print(f"warning: could not stop {name}: {exc}", flush=True)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Start the Enterprise API Security Auditor stack.")
    parser.add_argument("--skip-redis-test", action="store_true",
                        help="skip the optional :5002 Redis harness")
    parser.add_argument("--skip-frontend", action="store_true",
                        help="do not start the React dashboard")
    parser.add_argument("--timeout", type=int, default=90,
                        help="seconds to wait per service health check")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    plan = services_to_run(skip_redis_test=args.skip_redis_test,
                           skip_frontend=args.skip_frontend)
    problem = preflight(
        want_frontend=any(s["npm"] for s in plan))
    if problem:
        print(f"error: {problem}", flush=True)
        return EXIT_PREFLIGHT

    launched = []
    try:
        for service in plan:
            name = service["key"]
            if service["npm"]:
                print(f"[start] {name}: npm start (frontend/)", flush=True)
                launched.append((name, launch_frontend()))
                print(f"[start] {name}: launched at "
                      "http://localhost:3000", flush=True)
                continue
            url = f"http://localhost:{service['port']}{service['health']}"
            if not port_occupied(service["port"]):
                # Fast path: free port, launch immediately. The HTTP
                # probe below only matters when something holds the
                # port, and on hosts with slow loopback refusal it
                # would stall here for the full timeout per service.
                print(f"[start] {name}: {service['script']} "
                      f"(waiting for {url})", flush=True)
                try:
                    proc = launch_python(service["script"])
                except FileNotFoundError as exc:
                    print(f"error: {exc}", flush=True)
                    stop_all(launched)
                    return EXIT_FAILED
                launched.append((name, proc))
                ok, detail = wait_for_health(proc, url, args.timeout)
                if not ok:
                    print(f"error: {name} failed to start: {detail}. "
                          "Stopping services started by this run.",
                          flush=True)
                    stop_all(launched)
                    return EXIT_FAILED
                print(f"[start] {name}: up at "
                      f"http://localhost:{service['port']}", flush=True)
                continue
            # Something holds the port: either an already-running
            # service to skip, or a stuck process to report. Give a
            # starting service time to answer before deciding.
            print(f"[start] {name}: port {service['port']} in use, "
                  "checking it...", flush=True)
            if is_serving(url, timeout=20):
                print(f"[start] {name}: already serving "
                      f"http://localhost:{service['port']} "
                      "(skipped)", flush=True)
                continue
            print(f"error: port {service['port']} is already held by "
                  f"a process that is not answering {url}. Stop that "
                  f"process (or wait for it to finish starting) and "
                  "rerun; refusing to start a duplicate.",
                  flush=True)
            stop_all(launched)
            return EXIT_FAILED
    except KeyboardInterrupt:
        print("\n[start] interrupted; stopping launched services...",
              flush=True)
        stop_all(launched)
        return EXIT_FAILED

    if os.name == "nt":
        print("[start] all services launched in their own windows.",
              flush=True)
        return EXIT_OK
    print("[start] all services running; press Ctrl+C to stop them.",
          flush=True)
    try:
        while True:
            for name, proc in launched:
                if proc.poll() is not None:
                    print(f"error: {name} exited with code "
                          f"{proc.returncode}; stopping the rest.",
                          flush=True)
                    stop_all(launched)
                    return EXIT_FAILED
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[start] stopping services...", flush=True)
        stop_all(launched)
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
