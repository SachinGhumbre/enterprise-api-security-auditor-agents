#!/usr/bin/env bash
# All-in-one container entrypoint: validate .env, render the dashboard's
# runtime config, then supervise Redis + 3 Flask APIs + nginx.
set -euo pipefail

export ENV_FILE="${ENV_FILE:-/app/backend/.env}"

echo "[entrypoint] env file: $ENV_FILE"
if [ ! -f "$ENV_FILE" ]; then
  echo "[entrypoint] ERROR: $ENV_FILE not found."
  echo "[entrypoint] Copy the template, set META_API_KEY, then restart:"
  echo "[entrypoint]   cp .env.example .env   # then edit META_API_KEY inside"
  echo "[entrypoint]   docker compose up -d --build"
  exit 1
fi

# Warn (don't block) when the Meta key is missing: the dashboard, knowledge
# search and Redis diagnostics work offline, but audit / remediation /
# assistant LLM calls need it.
python3 - "$ENV_FILE" <<'EOF'
import sys
try:
    from dotenv import dotenv_values
except ImportError:  # requirements not installed yet (should not happen)
    sys.exit(0)
cfg = dotenv_values(sys.argv[1])
if not (cfg.get("META_API_KEY") or "").strip():
    print("[entrypoint] WARNING: META_API_KEY is empty in .env - "
          "audit/remediation/assistant LLM calls will fail.")
    print("[entrypoint] WARNING: paste a key from "
          "https://dev.meta.ai/products/meta-model-api and restart the container.")
else:
    print("[entrypoint] META_API_KEY present.")
EOF

mkdir -p /data /app/backend/artifacts

# Render the dashboard's runtime config from .env so demo passwords/keys and
# service URLs can change without rebuilding the image.
python3 - "$ENV_FILE" /app/frontend-build/runtime-config.js <<'EOF'
import json
import sys
from dotenv import dotenv_values

env_path, out_path = sys.argv[1], sys.argv[2]
cfg = dotenv_values(env_path)

def pick(*names, default=""):
    for name in names:
        value = (cfg.get(name) or "").strip()
        if value:
            return value
    return default

runtime = {
    "REACT_APP_AGENTS_URL": pick("REACT_APP_AGENTS_URL",
                                 default="http://localhost:5000"),
    "REACT_APP_KNOWLEDGE_URL": pick("REACT_APP_KNOWLEDGE_URL",
                                    default="http://localhost:5001"),
    "REACT_APP_REDIS_TEST_URL": pick("REACT_APP_REDIS_TEST_URL",
                                     default="http://localhost:5002"),
    "REACT_APP_ADMIN_PASSWORD": pick("REACT_APP_ADMIN_PASSWORD", default="admin"),
    "REACT_APP_OPERATOR_PASSWORD": pick("REACT_APP_OPERATOR_PASSWORD", default="operator"),
    "REACT_APP_VIEWER_PASSWORD": pick("REACT_APP_VIEWER_PASSWORD", default="viewer"),
    "REACT_APP_ADMIN_KEY": pick("REACT_APP_ADMIN_KEY", default="admin"),
    "REACT_APP_OPERATOR_KEY": pick("REACT_APP_OPERATOR_KEY", default="operator"),
    "REACT_APP_VIEWER_KEY": pick("REACT_APP_VIEWER_KEY", default="viewer"),
}
with open(out_path, "w", encoding="utf-8") as handle:
    handle.write("// Generated at container startup from .env - do not edit.\n")
    handle.write("window.__RUNTIME_CONFIG__ = ")
    json.dump(runtime, handle)
    handle.write(";\n")
print("[entrypoint] wrote dashboard runtime config.")
EOF

# First-boot corpus ingest runs in the background; it never blocks startup.
nohup python3 /app/docker/auto_ingest.py > /tmp/auto_ingest.log 2>&1 &

exec /usr/bin/supervisord -c /app/docker/supervisord.conf
