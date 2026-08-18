"""Detectors for unattached (orphaned) block storage volumes."""

from __future__ import annotations

from typing import Any, ClassVar

from openstack.connection import Connection
from openstack.exceptions import ForbiddenException

from openstack_janitor.detectors.base import Detector, Finding
from openstack_janitor.safety import safety_fields


def _list_volumes(conn: Connection) -> list[Any]:
    """List volumes across all projects, falling back to the caller's own project."""
    try:
        return list(conn.block_storage.volumes(details=True, all_projects=True))
    except ForbiddenException:
        # all_projects=True requires admin; fall back to the caller's own project.
        return list(conn.block_storage.volumes(details=True))


def _list_snapshot_volume_ids(conn: Connection) -> set[str]:
    """Return the set of volume ids that have at least one snapshot.

    Uses the same admin ``all_projects`` list with a ``ForbiddenException``
    fallback to project scope as the volume list, so the two scopes agree in
    the common cases (admin sees all of both; a non-admin sees only their own
    project's both). A falsy ``volume_id`` is skipped defensively.
    """
    try:
        snapshots = list(conn.block_storage.snapshots(details=True, all_projects=True))
    except ForbiddenException:
        # all_projects=True requires admin; fall back to the caller's own project.
        snapshots = list(conn.block_storage.snapshots(details=True))
    return {vid for snap in snapshots if (vid := getattr(snap, "volume_id", None))}


class UnattachedVolumesDetector(Detector):
    """Flags volumes that are "available" (i.e. not attached to any server)."""

    name: ClassVar[str] = "unattached-volumes"
    description: ClassVar[str] = "Volumes in 'available' state with no attachments"

    def detect(self, conn: Connection) -> list[Finding]:
        findings: list[Finding] = []
        for vol in _list_volumes(conn):
            if vol.status != "available" or vol.attachments:
                continue
            findings.append(
                Finding(
                    resource_type="volume",
                    resource_id=vol.id,
                    resource_name=vol.name or "",
                    project_id=getattr(vol, "project_id", "") or "",
                    reason="volume is unattached (status=available)",
                    **safety_fields(vol),
                )
            )
        return findings

    def clean(self, conn: Connection, finding: Finding) -> None:
        conn.block_storage.delete_volume(finding.resource_id, ignore_missing=True)


class UnattachedVolumesNoSnapshotsDetector(Detector):
    """Flags unattached "available" volumes that have no dependent snapshots.

    This is the subset of :class:`UnattachedVolumesDetector` that is actually
    safe to delete: Cinder refuses to delete a volume that still has snapshots,
    so those are reported by ``unattached-volumes`` but not here.
    """

    name: ClassVar[str] = "unattached-volumes-no-snapshots"
    description: ClassVar[str] = "Volumes in 'available' state with no attachments and no snapshots"

    def detect(self, conn: Connection) -> list[Finding]:
        volumes = _list_volumes(conn)
        volume_ids_with_snapshots = _list_snapshot_volume_ids(conn)

        findings: list[Finding] = []
        for vol in volumes:
            if vol.status != "available" or vol.attachments:
                continue
            if vol.id in volume_ids_with_snapshots:
                continue
            findings.append(
                Finding(
                    resource_type="volume",
                    resource_id=vol.id,
                    resource_name=vol.name or "",
                    project_id=getattr(vol, "project_id", "") or "",
                    reason="volume is unattached (status=available) and has no snapshots",
                    **safety_fields(vol),
                )
            )
        return findings

    def clean(self, conn: Connection, finding: Finding) -> None:
        conn.block_storage.delete_volume(finding.resource_id, ignore_missing=True)
