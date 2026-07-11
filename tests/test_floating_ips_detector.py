"""Tests for the unassociated-floating-ips detector."""

from __future__ import annotations

from openstack_janitor.detectors.floating_ips import UnassociatedFloatingIpsDetector


def test_finds_unassociated_floating_ip(fake_conn, fake_floating_ip) -> None:
    fip = fake_floating_ip(port_id=None)
    fake_conn.network.ips.return_value = [fip]

    findings = UnassociatedFloatingIpsDetector().detect(fake_conn)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.resource_type == "floating-ip"
    assert finding.resource_id == fip.id
    assert finding.resource_name == fip.floating_ip_address
    assert finding.project_id == fip.project_id
    assert "not associated" in finding.reason


def test_ignores_associated_floating_ip(fake_conn, fake_floating_ip) -> None:
    fip = fake_floating_ip(port_id="port-1234")
    fake_conn.network.ips.return_value = [fip]

    findings = UnassociatedFloatingIpsDetector().detect(fake_conn)

    assert findings == []


def test_extra_contains_status(fake_conn, fake_floating_ip) -> None:
    fip = fake_floating_ip(port_id=None, status="DOWN")
    fake_conn.network.ips.return_value = [fip]

    findings = UnassociatedFloatingIpsDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].extra == {"status": "DOWN"}


def test_resource_name_uses_floating_ip_address(fake_conn, fake_floating_ip) -> None:
    fip = fake_floating_ip(port_id=None, floating_ip_address="203.0.113.20")
    fake_conn.network.ips.return_value = [fip]

    findings = UnassociatedFloatingIpsDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].resource_name == "203.0.113.20"


def test_extra_empty_when_status_missing(fake_conn, fake_floating_ip) -> None:
    fip = fake_floating_ip(port_id=None, status=None)
    fake_conn.network.ips.return_value = [fip]

    findings = UnassociatedFloatingIpsDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].extra == {}


def test_floating_ip_address_none_is_handled(fake_conn, fake_floating_ip) -> None:
    fip = fake_floating_ip(port_id=None, floating_ip_address=None)
    fake_conn.network.ips.return_value = [fip]

    findings = UnassociatedFloatingIpsDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].resource_name == ""
