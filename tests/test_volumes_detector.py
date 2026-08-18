"""Tests for the unattached-volumes detectors."""

from __future__ import annotations

from openstack.exceptions import ForbiddenException

from openstack_janitor.detectors.base import Finding
from openstack_janitor.detectors.volumes import (
    UnattachedVolumesDetector,
    UnattachedVolumesNoSnapshotsDetector,
)


def test_finds_unattached_available_volume(fake_conn, fake_volume) -> None:
    vol = fake_volume(status="available", attachments=[])
    fake_conn.block_storage.volumes.return_value = [vol]

    findings = UnattachedVolumesDetector().detect(fake_conn)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.resource_type == "volume"
    assert finding.resource_id == vol.id
    assert finding.resource_name == vol.name
    assert finding.project_id == vol.project_id
    assert "unattached" in finding.reason


def test_ignores_in_use_volume_with_attachments(fake_conn, fake_volume) -> None:
    vol = fake_volume(status="in-use", attachments=[{"server_id": "srv-1"}])
    fake_conn.block_storage.volumes.return_value = [vol]

    findings = UnattachedVolumesDetector().detect(fake_conn)

    assert findings == []


def test_ignores_available_but_attached_edge_case(fake_conn, fake_volume) -> None:
    # Defensive: a volume reporting "available" status but with a stale/leftover
    # attachment record should not be flagged as an orphan.
    vol = fake_volume(status="available", attachments=[{"server_id": "srv-1"}])
    fake_conn.block_storage.volumes.return_value = [vol]

    findings = UnattachedVolumesDetector().detect(fake_conn)

    assert findings == []


def test_falls_back_when_all_projects_forbidden(fake_conn, fake_volume) -> None:
    vol = fake_volume(status="available", attachments=[])

    def volumes_side_effect(*args, **kwargs):
        if kwargs.get("all_projects"):
            raise ForbiddenException("not admin")
        return [vol]

    fake_conn.block_storage.volumes.side_effect = volumes_side_effect

    findings = UnattachedVolumesDetector().detect(fake_conn)

    assert len(findings) == 1
    assert fake_conn.block_storage.volumes.call_count == 2
    first_call_kwargs = fake_conn.block_storage.volumes.call_args_list[0].kwargs
    second_call_kwargs = fake_conn.block_storage.volumes.call_args_list[1].kwargs
    assert first_call_kwargs.get("all_projects") is True
    assert "all_projects" not in second_call_kwargs


def test_name_none_is_handled(fake_conn, fake_volume) -> None:
    vol = fake_volume(status="available", attachments=[], name=None)
    fake_conn.block_storage.volumes.return_value = [vol]

    findings = UnattachedVolumesDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].resource_name == ""


def test_finding_carries_markers_from_metadata(fake_conn, fake_volume) -> None:
    vol = fake_volume(
        status="available", attachments=[], metadata={"janitor:keep": "true", "owner": "team-a"}
    )
    fake_conn.block_storage.volumes.return_value = [vol]

    findings = UnattachedVolumesDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].markers == ("janitor:keep", "owner")


def test_clean_deletes_volume_by_id(fake_conn) -> None:
    finding = Finding(
        resource_type="volume",
        resource_id="vol-0001",
        resource_name="test-volume",
        project_id="project-0001",
        reason="volume is unattached (status=available)",
    )

    UnattachedVolumesDetector().clean(fake_conn, finding)

    fake_conn.block_storage.delete_volume.assert_called_once_with("vol-0001", ignore_missing=True)


# --- unattached-volumes-no-snapshots ---------------------------------------


def test_no_snapshots_finds_volume_without_snapshots(fake_conn, fake_volume) -> None:
    vol = fake_volume(status="available", attachments=[])
    fake_conn.block_storage.volumes.return_value = [vol]
    fake_conn.block_storage.snapshots.return_value = []

    findings = UnattachedVolumesNoSnapshotsDetector().detect(fake_conn)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.resource_type == "volume"
    assert finding.resource_id == vol.id
    assert finding.resource_name == vol.name
    assert finding.project_id == vol.project_id
    assert "no snapshots" in finding.reason


def test_no_snapshots_ignores_volume_with_a_snapshot(fake_conn, fake_volume, fake_snapshot) -> None:
    vol = fake_volume(status="available", attachments=[])
    fake_conn.block_storage.volumes.return_value = [vol]
    fake_conn.block_storage.snapshots.return_value = [fake_snapshot(volume_id=vol.id)]

    findings = UnattachedVolumesNoSnapshotsDetector().detect(fake_conn)

    assert findings == []


def test_no_snapshots_ignores_in_use_volume(fake_conn, fake_volume) -> None:
    vol = fake_volume(status="in-use", attachments=[{"server_id": "srv-1"}])
    fake_conn.block_storage.volumes.return_value = [vol]
    fake_conn.block_storage.snapshots.return_value = []

    findings = UnattachedVolumesNoSnapshotsDetector().detect(fake_conn)

    assert findings == []


def test_no_snapshots_snapshot_of_other_volume_does_not_shield(
    fake_conn, fake_volume, fake_snapshot
) -> None:
    # A snapshot belonging to a *different* volume must not stop this one being flagged.
    vol = fake_volume(id="vol-target", status="available", attachments=[])
    fake_conn.block_storage.volumes.return_value = [vol]
    fake_conn.block_storage.snapshots.return_value = [fake_snapshot(volume_id="vol-other")]

    findings = UnattachedVolumesNoSnapshotsDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].resource_id == "vol-target"


def test_no_snapshots_falls_back_when_all_projects_forbidden(fake_conn, fake_volume) -> None:
    vol = fake_volume(status="available", attachments=[])

    def volumes_side_effect(*args, **kwargs):
        if kwargs.get("all_projects"):
            raise ForbiddenException("not admin")
        return [vol]

    def snapshots_side_effect(*args, **kwargs):
        if kwargs.get("all_projects"):
            raise ForbiddenException("not admin")
        return []

    fake_conn.block_storage.volumes.side_effect = volumes_side_effect
    fake_conn.block_storage.snapshots.side_effect = snapshots_side_effect

    findings = UnattachedVolumesNoSnapshotsDetector().detect(fake_conn)

    assert len(findings) == 1
    assert fake_conn.block_storage.volumes.call_count == 2
    assert fake_conn.block_storage.snapshots.call_count == 2
    assert "all_projects" not in fake_conn.block_storage.volumes.call_args_list[1].kwargs
    assert "all_projects" not in fake_conn.block_storage.snapshots.call_args_list[1].kwargs


def test_no_snapshots_name_none_is_handled(fake_conn, fake_volume) -> None:
    vol = fake_volume(status="available", attachments=[], name=None)
    fake_conn.block_storage.volumes.return_value = [vol]
    fake_conn.block_storage.snapshots.return_value = []

    findings = UnattachedVolumesNoSnapshotsDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].resource_name == ""


def test_no_snapshots_finding_carries_markers_from_metadata(fake_conn, fake_volume) -> None:
    vol = fake_volume(
        status="available", attachments=[], metadata={"janitor:keep": "true", "owner": "team-a"}
    )
    fake_conn.block_storage.volumes.return_value = [vol]
    fake_conn.block_storage.snapshots.return_value = []

    findings = UnattachedVolumesNoSnapshotsDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].markers == ("janitor:keep", "owner")


def test_no_snapshots_clean_deletes_volume_by_id(fake_conn) -> None:
    finding = Finding(
        resource_type="volume",
        resource_id="vol-0001",
        resource_name="test-volume",
        project_id="project-0001",
        reason="volume is unattached (status=available) and has no snapshots",
    )

    UnattachedVolumesNoSnapshotsDetector().clean(fake_conn, finding)

    fake_conn.block_storage.delete_volume.assert_called_once_with("vol-0001", ignore_missing=True)
