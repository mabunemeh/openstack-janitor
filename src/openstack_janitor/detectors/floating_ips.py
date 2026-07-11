"""Detector for unassociated floating IPs."""

from __future__ import annotations

from typing import ClassVar

from openstack.connection import Connection

from openstack_janitor.detectors.base import Detector, Finding


class UnassociatedFloatingIpsDetector(Detector):
    """Flags floating IPs that are not associated with any port."""

    name: ClassVar[str] = "unassociated-floating-ips"
    description: ClassVar[str] = "Floating IPs not associated with any port"

    def detect(self, conn: Connection) -> list[Finding]:
        # Unlike block storage, Neutron scopes list results by policy automatically
        # (admins see all projects, non-admins see only their own), so there is no
        # all_projects kwarg here and no ForbiddenException fallback is needed.
        ips = list(conn.network.ips())

        findings: list[Finding] = []
        for ip in ips:
            if ip.port_id:
                continue
            extra = {}
            status = getattr(ip, "status", None)
            if status:
                extra["status"] = str(status)
            findings.append(
                Finding(
                    resource_type="floating-ip",
                    resource_id=ip.id,
                    resource_name=getattr(ip, "floating_ip_address", "") or "",
                    project_id=getattr(ip, "project_id", "") or "",
                    reason="floating IP is not associated with any port",
                    extra=extra,
                )
            )
        return findings
