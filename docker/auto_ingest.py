#!/usr/bin/env python3
"""Background first-boot ingest for the all-in-one container.

Waits for the Knowledge API, then ingests the policy corpus when the vector
index is empty. Best effort: every failure is logged and the container keeps
running - the Knowledge page can always ingest manually.
"""

import json
import os
import time
import urllib.error
import urllib.request

ENV_PATH = os.getenv("ENV_FILE", "/app/backend/.env")
KNOWLEDGE_URL = "http://127.0.0.1:5001"
API_PREFIX = "/api/v1/knowledge"
STARTUP_WAIT_S = 180
POLL_S = 3


def read_env_value(name):
    """Minimal `.env` reader tolerant of `KEY = value` and quotes."""
    try:
        with open(ENV_PATH, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                if key.strip() == name:
                    return value.strip().strip("'\"").strip() or None
    except OSError:
        return None
    return None


def api_key():
    for name in ("ADMIN_API_KEYS", "OPERATOR_API_KEYS"):
        raw = read_env_value(name)
        if raw:
            return raw.split(",")[0].strip()
    return None


def call(method, path, payload=None, timeout=30):
    headers = {"Content-Type": "application/json"}
    key = api_key()
    if key:
        headers["X-API-Key"] = key
    request = urllib.request.Request(
        KNOWLEDGE_URL + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
        return response.status, (json.loads(body) if body else {})


def main():
    deadline = time.time() + STARTUP_WAIT_S
    while time.time() < deadline:
        try:
            status, _ = call("GET", f"{API_PREFIX}/health", timeout=5)
            if status == 200:
                break
        except Exception:
            time.sleep(POLL_S)
    else:
        print("[auto-ingest] knowledge API never became ready; skipping.")
        return

    try:
        _, stats = call("GET", f"{API_PREFIX}/stats", timeout=15)
    except Exception as exc:
        print(f"[auto-ingest] stats probe failed ({exc}); skipping.")
        return

    stored = stats.get("stored_chunks", 0) or 0
    if stored > 0:
        print(f"[auto-ingest] index already holds {stored} chunks; skipping.")
        return

    print("[auto-ingest] index empty; ingesting policy corpus...")
    try:
        _, result = call("POST", f"{API_PREFIX}/ingest",
                         payload={"reset": True}, timeout=300)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        print(f"[auto-ingest] ingest failed (HTTP {exc.code}): {detail}")
        return
    except Exception as exc:
        print(f"[auto-ingest] ingest failed ({exc}).")
        return
    print(f"[auto-ingest] done: {result.get('total_chunks', '?')} chunks "
          f"from {result.get('files_processed', '?')} files.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # never take the container down
        print(f"[auto-ingest] unexpected error ({exc}); skipping.")
