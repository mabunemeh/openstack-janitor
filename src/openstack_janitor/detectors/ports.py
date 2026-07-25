"""Detector for orphaned ports."""

from __future__ import annotations

from typing import ClassVar

from openstack.connection import Connection

from openstack_janitor.detectors.base import Detector, Finding


class OrphanedPortsDetector(Detector):
    """Flags ports that have no device owner and no device id.

    Infrastructure ports (DHCP, router interfaces, Octavia VIPs) always carry
    a device owner or device id, so they are never flagged. Known false
    positive: a manually pre-created port awaiting later attachment also has
    both fields empty. That is fine for a read-only audit, but any future
    clean action on ports must be gated behind age/tag safety rails rather
    than this signal alone.
    """

    name: ClassVar[str] = "orphaned-ports"
    description: ClassVar[str] = "Ports with no device owner and no device id"

    def detect(self, conn: Connection) -> list[Finding]:
        ports = list(conn.network.ports())

        findings: list[Finding] = []
        for port in ports:
            if port.device_owner or port.device_id:
                continue
            extra = {}
            if getattr(port, "network_id", None):
                extra["network_id"] = str(port.network_id)
            findings.append(
                Finding(
                    resource_type="port",
                    resource_id=port.id,
                    resource_name=port.name or "",
                    project_id=getattr(port, "project_id", "") or "",
                    reason="port has no device owner or device id",
                    extra=extra,
                )
            )
        return findings

    def clean(self, conn: Connection, finding: Finding) -> None:
        conn.network.delete_port(finding.resource_id, ignore_missing=True)
