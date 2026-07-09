"""Shared pytest fixtures: fake volumes and a mocked SDK connection.

Tests never touch the network -- every "connection" is a MagicMock.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest


def fake_volume(**overrides: Any) -> SimpleNamespace:
    """Build a fake openstacksdk volume resource with sane defaults."""
    defaults = {
        "id": "vol-0001",
        "name": "test-volume",
        "status": "available",
        "attachments": [],
        "project_id": "project-0001",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


@pytest.fixture
def fake_conn() -> MagicMock:
    """A MagicMock standing in for an openstack.connection.Connection."""
    conn = MagicMock()
    conn.block_storage.volumes.return_value = []
    return conn
