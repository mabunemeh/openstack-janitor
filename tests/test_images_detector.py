"""Tests for the orphan-snapshot-images detector."""

from __future__ import annotations

import json

from openstack.exceptions import ForbiddenException, NotFoundException

from openstack_janitor.detectors.base import Finding
from openstack_janitor.detectors.images import OrphanSnapshotImagesDetector


def _bdm_json(*snapshot_ids: str, include_source_type: bool = True) -> str:
    entries = []
    for i, sid in enumerate(snapshot_ids):
        entry: dict[str, object] = {
            "snapshot_id": sid,
            "destination_type": "volume",
            "boot_index": i,
            "device_name": f"/dev/vd{'abcdefgh'[i]}",
        }
        if include_source_type:
            entry["source_type"] = "snapshot"
        entries.append(entry)
    return json.dumps(entries)


def test_finds_image_with_missing_snapshot(fake_conn, fake_image, fake_snapshot) -> None:
    img = fake_image(
        properties={"block_device_mapping": _bdm_json("snap-gone")},
    )
    fake_conn.image.images.return_value = [img]
    fake_conn.block_storage.snapshots.return_value = [
        fake_snapshot(id="snap-other"),
    ]

    findings = OrphanSnapshotImagesDetector().detect(fake_conn)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.resource_type == "image"
    assert finding.resource_id == img.id
    assert finding.resource_name == img.name
    assert finding.project_id == img.owner
    assert "missing snapshot" in finding.reason
    assert finding.extra["missing_snapshot_ids"] == "snap-gone"


def test_ignores_image_whose_snapshot_exists(fake_conn, fake_image, fake_snapshot) -> None:
    img = fake_image(
        properties={"block_device_mapping": _bdm_json("snap-0001")},
    )
    fake_conn.image.images.return_value = [img]
    fake_conn.block_storage.snapshots.return_value = [fake_snapshot(id="snap-0001")]

    findings = OrphanSnapshotImagesDetector().detect(fake_conn)

    assert findings == []


def test_ignores_qcow_image_without_bdm(fake_conn, fake_image) -> None:
    img = fake_image(properties={"stores": "default_backend"})
    fake_conn.image.images.return_value = [img]

    findings = OrphanSnapshotImagesDetector().detect(fake_conn)

    assert findings == []


def test_flags_when_any_of_multiple_snapshots_missing(fake_conn, fake_image, fake_snapshot) -> None:
    img = fake_image(
        properties={"block_device_mapping": _bdm_json("snap-ok", "snap-gone")},
    )
    fake_conn.image.images.return_value = [img]
    fake_conn.block_storage.snapshots.return_value = [fake_snapshot(id="snap-ok")]

    findings = OrphanSnapshotImagesDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].extra["missing_snapshot_ids"] == "snap-gone"


def test_includes_hidden_images(fake_conn, fake_image) -> None:
    hidden = fake_image(
        id="img-hidden",
        name="hidden-image",
        is_hidden=True,
        properties={"block_device_mapping": _bdm_json("snap-gone")},
    )

    def images_side_effect(*args, **kwargs):
        if kwargs.get("is_hidden"):
            return [hidden]
        return []

    fake_conn.image.images.side_effect = images_side_effect
    fake_conn.block_storage.snapshots.return_value = []

    findings = OrphanSnapshotImagesDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].resource_id == "img-hidden"
    assert findings[0].extra["os_hidden"] == "true"
    assert fake_conn.image.images.call_count == 2


def test_malformed_bdm_is_skipped(fake_conn, fake_image) -> None:
    img = fake_image(properties={"block_device_mapping": "not-json{"})
    fake_conn.image.images.return_value = [img]

    findings = OrphanSnapshotImagesDetector().detect(fake_conn)

    assert findings == []


def test_reads_img_block_device_mapping(fake_conn, fake_image) -> None:
    img = fake_image(
        properties={"img_block_device_mapping": _bdm_json("snap-gone")},
    )
    fake_conn.image.images.return_value = [img]
    fake_conn.block_storage.snapshots.return_value = []

    findings = OrphanSnapshotImagesDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].extra["missing_snapshot_ids"] == "snap-gone"


def test_legacy_bdm_without_source_type(fake_conn, fake_image) -> None:
    img = fake_image(
        properties={
            "block_device_mapping": _bdm_json("snap-gone", include_source_type=False),
        },
    )
    fake_conn.image.images.return_value = [img]
    fake_conn.block_storage.snapshots.return_value = []

    findings = OrphanSnapshotImagesDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].extra["missing_snapshot_ids"] == "snap-gone"


def test_ignores_bdm_with_non_snapshot_source_type(fake_conn, fake_image) -> None:
    bdm = json.dumps([{"source_type": "volume", "snapshot_id": "snap-stale", "volume_id": "vol-1"}])
    img = fake_image(properties={"block_device_mapping": bdm})
    fake_conn.image.images.return_value = [img]
    fake_conn.block_storage.snapshots.return_value = []

    findings = OrphanSnapshotImagesDetector().detect(fake_conn)

    assert findings == []


def test_falls_back_when_all_projects_forbidden(fake_conn, fake_image, fake_snapshot) -> None:
    img = fake_image(
        properties={"block_device_mapping": _bdm_json("snap-gone")},
    )
    fake_conn.image.images.return_value = [img]

    def snapshots_side_effect(*args, **kwargs):
        if kwargs.get("all_projects"):
            raise ForbiddenException("not admin")
        return [fake_snapshot(id="snap-other")]

    fake_conn.block_storage.snapshots.side_effect = snapshots_side_effect
    fake_conn.block_storage.get_snapshot.side_effect = NotFoundException("gone")

    findings = OrphanSnapshotImagesDetector().detect(fake_conn)

    assert len(findings) == 1
    assert fake_conn.block_storage.snapshots.call_count == 2
    first_call_kwargs = fake_conn.block_storage.snapshots.call_args_list[0].kwargs
    second_call_kwargs = fake_conn.block_storage.snapshots.call_args_list[1].kwargs
    assert first_call_kwargs.get("all_projects") is True
    assert "all_projects" not in second_call_kwargs
    fake_conn.block_storage.get_snapshot.assert_called_once_with("snap-gone")


def test_project_scoped_list_does_not_false_positive_on_foreign_snapshot(
    fake_conn, fake_image, fake_snapshot
) -> None:
    # Shared/public image from another project; snapshot exists but is invisible
    # to the project-scoped list — get_snapshot confirms it still exists.
    img = fake_image(
        owner="other-project",
        properties={"block_device_mapping": _bdm_json("snap-foreign")},
    )
    fake_conn.image.images.return_value = [img]

    def snapshots_side_effect(*args, **kwargs):
        if kwargs.get("all_projects"):
            raise ForbiddenException("not admin")
        return []

    fake_conn.block_storage.snapshots.side_effect = snapshots_side_effect
    fake_conn.block_storage.get_snapshot.return_value = fake_snapshot(id="snap-foreign")

    findings = OrphanSnapshotImagesDetector().detect(fake_conn)

    assert findings == []
    fake_conn.block_storage.get_snapshot.assert_called_once_with("snap-foreign")


def test_project_scoped_list_skips_when_get_snapshot_forbidden(fake_conn, fake_image) -> None:
    img = fake_image(
        owner="other-project",
        properties={"block_device_mapping": _bdm_json("snap-forbidden")},
    )
    fake_conn.image.images.return_value = [img]

    def snapshots_side_effect(*args, **kwargs):
        if kwargs.get("all_projects"):
            raise ForbiddenException("not admin")
        return []

    fake_conn.block_storage.snapshots.side_effect = snapshots_side_effect
    fake_conn.block_storage.get_snapshot.side_effect = ForbiddenException("no access")

    findings = OrphanSnapshotImagesDetector().detect(fake_conn)

    assert findings == []


def test_name_none_and_owner_as_project_id(fake_conn, fake_image) -> None:
    img = fake_image(
        name=None,
        owner="proj-owner",
        properties={"block_device_mapping": _bdm_json("snap-gone")},
    )
    fake_conn.image.images.return_value = [img]
    fake_conn.block_storage.snapshots.return_value = []

    findings = OrphanSnapshotImagesDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].resource_name == ""
    assert findings[0].project_id == "proj-owner"


def test_clean_deletes_image_by_id(fake_conn) -> None:
    finding = Finding(
        resource_type="image",
        resource_id="img-0001",
        resource_name="test-image",
        project_id="project-0001",
        reason="image references missing snapshot(s): snap-gone",
    )

    OrphanSnapshotImagesDetector().clean(fake_conn, finding)

    fake_conn.image.delete_image.assert_called_once_with("img-0001", ignore_missing=True)
