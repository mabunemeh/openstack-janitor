"""Tests for the old-snapshots detector."""

from __future__ import annotations

from datetime import UTC, datetime

from openstack.exceptions import ForbiddenException

from openstack_janitor.detectors.snapshots import OldSnapshotsDetector

NOW = datetime(2026, 7, 13, tzinfo=UTC)


def test_finds_old_snapshot(fake_conn, fake_snapshot) -> None:
    snap = fake_snapshot(created_at="2026-01-01T00:00:00Z")
    fake_conn.block_storage.snapshots.return_value = [snap]

    findings = OldSnapshotsDetector(max_age_days=90.0, now=NOW).detect(fake_conn)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.resource_type == "snapshot"
    assert finding.resource_id == snap.id
    assert finding.resource_name == snap.name
    assert finding.project_id == snap.project_id
    assert "days old" in finding.reason
    assert finding.extra["created_at"] == "2026-01-01T00:00:00Z"
    assert finding.extra["volume_id"] == "vol-0001"


def test_ignores_recent_snapshot(fake_conn, fake_snapshot) -> None:
    snap = fake_snapshot(created_at="2026-07-10T00:00:00Z")
    fake_conn.block_storage.snapshots.return_value = [snap]

    findings = OldSnapshotsDetector(max_age_days=90.0, now=NOW).detect(fake_conn)

    assert findings == []


def test_exactly_at_threshold_is_not_flagged(fake_conn, fake_snapshot) -> None:
    # NOW - 90 days exactly.
    snap = fake_snapshot(created_at="2026-04-14T00:00:00Z")
    fake_conn.block_storage.snapshots.return_value = [snap]

    findings = OldSnapshotsDetector(max_age_days=90.0, now=NOW).detect(fake_conn)

    assert findings == []


def test_missing_created_at_is_skipped(fake_conn, fake_snapshot) -> None:
    snap = fake_snapshot(created_at=None)
    fake_conn.block_storage.snapshots.return_value = [snap]

    findings = OldSnapshotsDetector(max_age_days=90.0, now=NOW).detect(fake_conn)

    assert findings == []


def test_falls_back_when_all_projects_forbidden(fake_conn, fake_snapshot) -> None:
    snap = fake_snapshot(created_at="2026-01-01T00:00:00Z")

    def snapshots_side_effect(*args, **kwargs):
        if kwargs.get("all_projects"):
            raise ForbiddenException("not admin")
        return [snap]

    fake_conn.block_storage.snapshots.side_effect = snapshots_side_effect

    findings = OldSnapshotsDetector(max_age_days=90.0, now=NOW).detect(fake_conn)

    assert len(findings) == 1
    assert fake_conn.block_storage.snapshots.call_count == 2
    first_call_kwargs = fake_conn.block_storage.snapshots.call_args_list[0].kwargs
    second_call_kwargs = fake_conn.block_storage.snapshots.call_args_list[1].kwargs
    assert first_call_kwargs.get("all_projects") is True
    assert "all_projects" not in second_call_kwargs
