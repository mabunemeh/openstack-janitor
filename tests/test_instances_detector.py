"""Tests for the shutoff-instances detector."""

from __future__ import annotations

from datetime import datetime, timezone

from openstack.exceptions import ForbiddenException

from openstack_janitor.detectors.base import Finding
from openstack_janitor.detectors.instances import ShutoffInstancesDetector

NOW = datetime(2026, 7, 13, tzinfo=timezone.utc)


def test_finds_old_shutoff_instance(fake_conn, fake_server) -> None:
    server = fake_server(status="SHUTOFF", updated_at="2026-01-01T00:00:00Z")
    fake_conn.compute.servers.return_value = [server]

    findings = ShutoffInstancesDetector(max_age_days=30.0, now=NOW).detect(fake_conn)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.resource_type == "instance"
    assert finding.resource_id == server.id
    assert finding.resource_name == server.name
    assert finding.project_id == server.project_id
    assert "shutoff" in finding.reason
    assert finding.extra["updated_at"] == "2026-01-01T00:00:00Z"
    assert finding.extra["status"] == "SHUTOFF"


def test_ignores_recent_shutoff_instance(fake_conn, fake_server) -> None:
    server = fake_server(status="SHUTOFF", updated_at="2026-07-10T00:00:00Z")
    fake_conn.compute.servers.return_value = [server]

    findings = ShutoffInstancesDetector(max_age_days=30.0, now=NOW).detect(fake_conn)

    assert findings == []


def test_exactly_at_threshold_is_not_flagged(fake_conn, fake_server) -> None:
    # NOW minus exactly 30 days; the threshold comparison is strict.
    server = fake_server(status="SHUTOFF", updated_at="2026-06-13T00:00:00Z")
    fake_conn.compute.servers.return_value = [server]

    findings = ShutoffInstancesDetector(max_age_days=30.0, now=NOW).detect(fake_conn)

    assert findings == []


def test_ignores_old_active_instance(fake_conn, fake_server) -> None:
    server = fake_server(status="ACTIVE", updated_at="2026-01-01T00:00:00Z")
    fake_conn.compute.servers.return_value = [server]

    findings = ShutoffInstancesDetector(max_age_days=30.0, now=NOW).detect(fake_conn)

    assert findings == []


def test_missing_updated_at_is_skipped(fake_conn, fake_server) -> None:
    server = fake_server(status="SHUTOFF", updated_at=None)
    fake_conn.compute.servers.return_value = [server]

    findings = ShutoffInstancesDetector(max_age_days=30.0, now=NOW).detect(fake_conn)

    assert findings == []


def test_falls_back_when_all_projects_forbidden(fake_conn, fake_server) -> None:
    server = fake_server(status="SHUTOFF", updated_at="2026-01-01T00:00:00Z")

    def servers_side_effect(*args, **kwargs):
        if kwargs.get("all_projects"):
            raise ForbiddenException("not admin")
        return [server]

    fake_conn.compute.servers.side_effect = servers_side_effect

    findings = ShutoffInstancesDetector(max_age_days=30.0, now=NOW).detect(fake_conn)

    assert len(findings) == 1
    assert fake_conn.compute.servers.call_count == 2
    first_call_kwargs = fake_conn.compute.servers.call_args_list[0].kwargs
    second_call_kwargs = fake_conn.compute.servers.call_args_list[1].kwargs
    assert first_call_kwargs.get("all_projects") is True
    assert "all_projects" not in second_call_kwargs


def test_clean_deletes_server_by_id(fake_conn) -> None:
    finding = Finding(
        resource_type="instance",
        resource_id="srv-0001",
        resource_name="test-server",
        project_id="project-0001",
        reason="instance has been shutoff for at least 100 days (threshold 30)",
    )

    ShutoffInstancesDetector().clean(fake_conn, finding)

    fake_conn.compute.delete_server.assert_called_once_with("srv-0001", ignore_missing=True)
