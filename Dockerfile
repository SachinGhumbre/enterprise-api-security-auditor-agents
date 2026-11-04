# =============================================================================
# Enterprise API Security Auditor - all-in-one image.
#
# ONE image runs the whole stack under supervisord:
#   Redis Stack (:6379, container-internal) + Knowledge API (:5001) +
#   AI Agents API (:5000) + Redis harness (:5002) + React dashboard (:3000).
#
# Judges only need Docker + a .env file (see .env.example):
#   cp .env.example .env   # then set META_API_KEY
#   docker compose up -d --build
# =============================================================================

# ---- Stage 1: Redis Stack binaries (copied, never apt-installed) --------------
# The packages.redis.io apt repo is blocked on some networks; the official
# image always pulls from Docker Hub, so the binaries come from there.
FROM redis/redis-stack-server:latest AS redis-stack

# ---- Stage 2: build the React dashboard -------------------------------------
FROM node:20-slim AS frontend-builder

# react-scripts 5 needs the legacy OpenSSL provider on Node 17+.
ENV NODE_OPTIONS=--openssl-legacy-provider

WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- Stage 3: runtime (Python APIs + Redis Stack + nginx) -------------------
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive \
    REDIS_HARNESS_DEBUG=false

# nginx serves the dashboard, supervisord runs all five processes, curl backs
# the HEALTHCHECK, libgomp1/libssl3 are linked by the RediSearch module.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx supervisor curl libgomp1 libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Redis Stack with the RediSearch module (mandatory - plain redis cannot do
# vector search). The whole /opt/redis-stack tree is kept so the server finds
# its modules via its built-in relative paths.
COPY --from=redis-stack /opt/redis-stack /opt/redis-stack
ENV PATH="/opt/redis-stack/bin:${PATH}"

# Build-time gate: the binaries must link cleanly on this base image.
RUN redis-server --version \
    && test -z "$(ldd /opt/redis-stack/bin/redis-server | grep 'not found' || true)" \
    && echo "redis-stack link ok"

WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
RUN python3 -m pip install --upgrade pip \
    && python3 -m pip install -r backend/requirements.txt

# NOTE: backend/.env is excluded by .dockerignore (never bake secrets into the
# image). At runtime docker-compose.yml mounts the judge's .env to
# /app/backend/.env, which every service reads.
COPY backend/ ./backend/
COPY redis-test.py ./redis-test.py
COPY --from=frontend-builder /build/frontend/build ./frontend-build
COPY docker/ ./docker/
COPY docker/nginx.conf /etc/nginx/nginx.conf

RUN mkdir -p /data /app/backend/artifacts \
    && chmod +x /app/docker/entrypoint.sh \
    && sed -i 's/\r$//' /app/docker/entrypoint.sh /app/docker/supervisord.conf /etc/nginx/nginx.conf \
    && rm -f /etc/nginx/sites-enabled/default \
    && python3 -c "import flask, redis, langgraph; print('deps ok')"

# 3000 dashboard, 5000 agents, 5001 knowledge, 5002 harness.
# Redis :6379 stays container-internal (not published by docker-compose.yml).
EXPOSE 3000 5000 5001 5002

HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD curl -sf http://127.0.0.1:5000/api/v1/ai-agents/health > /dev/null || exit 1

ENTRYPOINT ["/app/docker/entrypoint.sh"]
