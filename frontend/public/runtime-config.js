// Dashboard runtime config. In the Docker image this file is REWRITTEN at
// container startup from .env (see docker/entrypoint.sh), so demo passwords,
// API keys and service URLs can change with a plain container restart.
// For local dev (`npm start` / `npm run build`) this placeholder is ignored
// and values fall back to REACT_APP_* from frontend/.env.
window.__RUNTIME_CONFIG__ = window.__RUNTIME_CONFIG__ || {};
