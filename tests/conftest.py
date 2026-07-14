"""Shared pytest fixtures: fake volumes and a mocked SDK connection.

Tests never touch the network -- every "connection" is a MagicMock.
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

VolumeFactory = Callable[..., SimpleNamespace]
FloatingIpFactory = Callable[..., SimpleNamespace]
PortFactory = Callable[..., SimpleNamespace]
SnapshotFactory = Callable[..., SimpleNamespace]
ServerFactory = Callable[..., SimpleNamespace]
SecurityGroupFactory = Callable[..., SimpleNamespace]


@pytest.fixture
def fake_volume() -> VolumeFactory:
    """Factory building fake openstacksdk volume resources with sane defaults."""

    def _make(**overrides: Any) -> SimpleNamespace:
        defaults = {
            "id": "vol-0001",
            "name": "test-volume",
            "status": "available",
            "attachments": [],
            "project_id": "project-0001",
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    return _make


@pytest.fixture
def fake_floating_ip() -> FloatingIpFactory:
    """Factory building fake openstacksdk floating IP resources with sane defaults."""

    def _make(**overrides: Any) -> SimpleNamespace:
        defaults = {
            "id": "fip-0001",
            "floating_ip_address": "203.0.113.10",
            "port_id": None,
            "project_id": "project-0001",
            "status": "DOWN",
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    return _make


@pytest.fixture
def fake_port() -> PortFactory:
    """Factory building fake openstacksdk port resources with sane defaults."""

    def _make(**overrides: Any) -> SimpleNamespace:
        defaults = {
            "id": "port-0001",
            "name": "test-port",
            "device_owner": "",
            "device_id": "",
            "network_id": "net-0001",
            "project_id": "project-0001",
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    return _make


@pytest.fixture
def fake_snapshot() -> SnapshotFactory:
    """Factory building fake openstacksdk snapshot resources with sane defaults."""

    def _make(**overrides: Any) -> SimpleNamespace:
        defaults = {
            "id": "snap-0001",
            "name": "test-snapshot",
            "created_at": "2026-01-01T00:00:00Z",
            "volume_id": "vol-0001",
            "project_id": "project-0001",
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    return _make


@pytest.fixture
def fake_server() -> ServerFactory:
    """Factory building fake openstacksdk server resources with sane defaults."""

    def _make(**overrides: Any) -> SimpleNamespace:
        defaults = {
            "id": "srv-0001",
            "name": "test-server",
            "status": "SHUTOFF",
            "updated_at": "2026-01-01T00:00:00Z",
            "project_id": "project-0001",
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    return _make


@pytest.fixture
def fake_security_group() -> SecurityGroupFactory:
    """Factory building fake openstacksdk security group resources with sane defaults."""

    def _make(**overrides: Any) -> SimpleNamespace:
        defaults = {
            "id": "sg-0001",
            "name": "test-sg",
            "project_id": "project-0001",
            "security_group_rules": [],
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    return _make


@pytest.fixture
def fake_conn() -> MagicMock:
    """A MagicMock standing in for an openstack.connection.Connection."""
    conn = MagicMock()
    conn.block_storage.volumes.return_value = []
    conn.block_storage.snapshots.return_value = []
    conn.network.ips.return_value = []
    conn.network.ports.return_value = []
    conn.network.security_groups.return_value = []
    conn.compute.servers.return_value = []
    return conn
