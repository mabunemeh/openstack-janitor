"""Detector for unused security groups."""

from __future__ import annotations

from typing import ClassVar

from openstack.connection import Connection

from openstack_janitor.detectors.base import Detector, Finding


class UnusedSecurityGroupsDetector(Detector):
    """Flags security groups that are not in use.

    A group is considered "in use" from two sources: it is attached to at
    least one port (via that port's ``security_group_ids``), or it is named
    as the ``remote_group_id`` of a rule on *any* security group -- a group
    referenced that way is in use even if it has zero ports, because
    deleting it would break the referencing rule. The auto-created "default"
    group present in every project is undeletable and always skipped, since
    flagging it would just be noise.

    A self-referencing rule (remote_group_id pointing at its own group)
    marks the group in-use — an under-report in the delete-safe direction.
    Known false positive: a freshly created group awaiting its first port is
    flagged. Fine for a read-only audit, but any future clean action must be
    gated behind age/tag safety rails rather than this signal alone.
    """

    name: ClassVar[str] = "unused-security-groups"
    description: ClassVar[str] = "Security groups not attached to any port or referenced by a rule"

    def detect(self, conn: Connection) -> list[Finding]:
        security_groups = list(conn.network.security_groups())
        ports = list(conn.network.ports())

        in_use_ids: set[str] = set()
        for port in ports:
            in_use_ids.update(getattr(port, "security_group_ids", []) or [])
        for group in security_groups:
            for rule in getattr(group, "security_group_rules", []) or []:
                if isinstance(rule, dict):
                    remote_group_id = rule.get("remote_group_id")
                else:
                    remote_group_id = getattr(rule, "remote_group_id", None)
                if remote_group_id:
                    in_use_ids.add(remote_group_id)

        findings: list[Finding] = []
        for group in security_groups:
            if group.id in in_use_ids:
                continue
            if (getattr(group, "name", None) or "") == "default":
                continue

            extra = {}
            rules = getattr(group, "security_group_rules", None)
            if rules is not None:
                extra["rules_count"] = str(len(rules))

            findings.append(
                Finding(
                    resource_type="security-group",
                    resource_id=group.id,
                    resource_name=getattr(group, "name", "") or "",
                    project_id=getattr(group, "project_id", "") or "",
                    reason="security group is not attached to any port or referenced by any rule",
                    extra=extra,
                )
            )
        return findings
