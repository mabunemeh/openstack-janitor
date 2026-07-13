"""Detector for old block storage snapshots."""

from __future__ import annotations

from datetime import datetime
from typing import ClassVar

from openstack.connection import Connection
from openstack.exceptions import ForbiddenException

from openstack_janitor.age import age_in_days
from openstack_janitor.detectors.base import Detector, Finding


class OldSnapshotsDetector(Detector):
    """Flags snapshots older than a configurable age threshold."""

    name: ClassVar[str] = "old-snapshots"
    description: ClassVar[str] = "Snapshots older than a configurable age threshold"

    def __init__(self, max_age_days: float = 90.0, *, now: datetime | None = None) -> None:
        self.max_age_days = max_age_days
        self.now = now

    def detect(self, conn: Connection) -> list[Finding]:
        try:
            snapshots = list(conn.block_storage.snapshots(details=True, all_projects=True))
        except ForbiddenException:
            # all_projects=True requires admin; fall back to the caller's own project.
            snapshots = list(conn.block_storage.snapshots(details=True))

        findings: list[Finding] = []
        for snap in snapshots:
            # Never flag what we can't date -- a missing/unparsable created_at
            # is skipped silently rather than guessed at.
            age = age_in_days(getattr(snap, "created_at", None), now=self.now)
            if age is None or age <= self.max_age_days:
                continue

            extra = {}
            created_at = getattr(snap, "created_at", None)
            if created_at:
                extra["created_at"] = str(created_at)
            volume_id = getattr(snap, "volume_id", None)
            if volume_id:
                extra["volume_id"] = str(volume_id)

            findings.append(
                Finding(
                    resource_type="snapshot",
                    resource_id=snap.id,
                    resource_name=getattr(snap, "name", "") or "",
                    project_id=getattr(snap, "project_id", "") or "",
                    reason=(f"snapshot is {age:.0f} days old (threshold {self.max_age_days:.0f})"),
                    extra=extra,
                )
            )
        return findings
