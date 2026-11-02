"""Suite-wide fixtures: hermetic defaults regardless of local .env.

A developer .env with API keys must not change endpoint behaviour under
test, so auth starts disabled here; test_auth.py enables it per test via
monkeypatch.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config  # noqa: E402

config.ADMIN_API_KEYS = []
config.OPERATOR_API_KEYS = []
config.VIEWER_API_KEYS = []
