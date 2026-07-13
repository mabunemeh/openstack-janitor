"""Detector for long-shutoff instances."""

from __future__ import annotations

from datetime import datetime
from typing import ClassVar

from openstack.connection import Connection
from openstack.exceptions import ForbiddenException

from openstack_janitor.age import age_in_days
from openstack_janitor.detectors.base import Detector, Finding


class ShutoffInstancesDetector(Detector):
    """Flags instances that have been SHUTOFF for longer than a threshold.

    There is no direct "shutoff since" field in the Compute API. Any status
    transition bumps ``updated_at``, so an ``updated_at`` older than N days
    on a currently-SHUTOFF server proves it has been off for at least N
    days -- a conservative lower bound, not an exact shutoff duration.
    Non-status mutations (metadata edits, resizes) also bump ``updated_at``,
    which can reset the apparent age and hide a genuinely old instance: this
    detector may under-report but never over-reports.
    """

    name: ClassVar[str] = "shutoff-instances"
    description: ClassVar[str] = "Instances that have been SHUTOFF for longer than a threshold"

    def __init__(self, max_age_days: float = 30.0, *, now: datetime | None = None) -> None:
        self.max_age_days = max_age_days
        self.now = now

    def detect(self, conn: Connection) -> list[Finding]:
        try:
            servers = list(conn.compute.servers(details=True, all_projects=True))
        except ForbiddenException:
            # all_projects=True requires admin; fall back to the caller's own project.
            servers = list(conn.compute.servers(details=True))

        findings: list[Finding] = []
        for server in servers:
            if server.status != "SHUTOFF":
                continue

            age = age_in_days(getattr(server, "updated_at", None), now=self.now)
            if age is None or age <= self.max_age_days:
                continue

            extra = {}
            updated_at = getattr(server, "updated_at", None)
            if updated_at:
                extra["updated_at"] = str(updated_at)
            status = getattr(server, "status", None)
            if status:
                extra["status"] = str(status)

            findings.append(
                Finding(
                    resource_type="instance",
                    resource_id=server.id,
                    resource_name=getattr(server, "name", "") or "",
                    project_id=getattr(server, "project_id", "") or "",
                    reason=(
                        f"instance has been shutoff for at least {age:.0f} days "
                        f"(threshold {self.max_age_days:.0f})"
                    ),
                    extra=extra,
                )
            )
        return findings
