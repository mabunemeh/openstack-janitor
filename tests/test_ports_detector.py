"""Tests for the orphaned-ports detector."""

from __future__ import annotations

from openstack_janitor.detectors.base import Finding
from openstack_janitor.detectors.ports import OrphanedPortsDetector


def test_finds_port_with_no_device_owner_or_id(fake_conn, fake_port) -> None:
    port = fake_port(device_owner="", device_id="")
    fake_conn.network.ports.return_value = [port]

    findings = OrphanedPortsDetector().detect(fake_conn)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.resource_type == "port"
    assert finding.resource_id == port.id
    assert finding.resource_name == port.name
    assert finding.project_id == port.project_id
    assert "no device owner or device id" in finding.reason


def test_ignores_attached_port(fake_conn, fake_port) -> None:
    port = fake_port(device_owner="compute:nova", device_id="srv-1")
    fake_conn.network.ports.return_value = [port]

    findings = OrphanedPortsDetector().detect(fake_conn)

    assert findings == []


def test_ignores_half_attached_port_with_only_device_id(fake_conn, fake_port) -> None:
    # A device_id with no device_owner is a half-attached edge case, not an orphan.
    port = fake_port(device_owner="", device_id="srv-1")
    fake_conn.network.ports.return_value = [port]

    findings = OrphanedPortsDetector().detect(fake_conn)

    assert findings == []


def test_name_none_is_handled(fake_conn, fake_port) -> None:
    port = fake_port(device_owner="", device_id="", name=None)
    fake_conn.network.ports.return_value = [port]

    findings = OrphanedPortsDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].resource_name == ""


def test_extra_contains_network_id(fake_conn, fake_port) -> None:
    port = fake_port(device_owner="", device_id="", network_id="net-9999")
    fake_conn.network.ports.return_value = [port]

    findings = OrphanedPortsDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].extra == {"network_id": "net-9999"}


def test_clean_deletes_port_by_id(fake_conn) -> None:
    finding = Finding(
        resource_type="port",
        resource_id="port-0001",
        resource_name="test-port",
        project_id="project-0001",
        reason="port has no device owner or device id",
    )

    OrphanedPortsDetector().clean(fake_conn, finding)

    fake_conn.network.delete_port.assert_called_once_with("port-0001", ignore_missing=True)
