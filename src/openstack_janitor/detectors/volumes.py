"""Detector for unattached (orphaned) block storage volumes."""

from __future__ import annotations

from typing import ClassVar

from openstack.connection import Connection
from openstack.exceptions import ForbiddenException

from openstack_janitor.detectors.base import Detector, Finding


class UnattachedVolumesDetector(Detector):
    """Flags volumes that are "available" (i.e. not attached to any server)."""

    name: ClassVar[str] = "unattached-volumes"
    description: ClassVar[str] = "Volumes in 'available' state with no attachments"

    def detect(self, conn: Connection) -> list[Finding]:
        try:
            volumes = list(conn.block_storage.volumes(details=True, all_projects=True))
        except ForbiddenException:
            # all_projects=True requires admin; fall back to the caller's own project.
            volumes = list(conn.block_storage.volumes(details=True))

        findings: list[Finding] = []
        for vol in volumes:
            if vol.status != "available" or vol.attachments:
                continue
            findings.append(
                Finding(
                    resource_type="volume",
                    resource_id=vol.id,
                    resource_name=vol.name or "",
                    project_id=getattr(vol, "project_id", "") or "",
                    reason="volume is unattached (status=available)",
                )
            )
        return findings
