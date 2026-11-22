import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# --- Isolated test environment -------------------------------------------------
# Set BEFORE importing skyla modules: config reads these at import time.
_TMP_DB_DIR = tempfile.mkdtemp(prefix="skyla-test-db-")
os.environ["SKYLA_DB_PATH"] = str(Path(_TMP_DB_DIR) / "test.db")

# Legacy admin token for tests (maps to the admin role for migration compatibility).
os.environ.setdefault("SKYLA_API_TOKEN", "test-legacy-token")
os.environ.setdefault("SKYLA_EXECUTION_PROVIDER", "namespace")

# --- Egress mode for the test suite -------------------------------------------
# Tests never intend to reach the network: outbound calls are either mocked
# (`httpx.MockTransport`) or replaced (monkeypatched `httpx.AsyncClient`). The
# suite therefore declares `legacy` mode explicitly. This is the ONLY sanctioned
# use of that mode, and `skyla.egress_client` refuses it whenever the network
# perimeter is installed, so it cannot leak into a real deployment. Tests that
# exercise enforcement pass `mode="enforce"`/`"policy"` explicitly instead.
os.environ["SKYLA_EGRESS_MODE"] = "legacy"
os.environ["SKYLA_EGRESS_ALLOW_LEGACY"] = "1"

import pytest

from skyla.db import Database

TEST_TOKEN = "test-legacy-token"
AUTH = {"Authorization": f"Bearer {TEST_TOKEN}"}


@pytest.fixture()
def db(tmp_path):
    """A fresh standalone database for unit-level DB tests."""
    return Database(str(tmp_path / "unit.db"))
