import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from skyla.db import Database


@pytest.fixture()
def db(tmp_path):
    return Database(str(tmp_path / "test.db"))
