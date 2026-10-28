"""Tests for the old-unused-images detector."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from openstack.exceptions import ForbiddenException

from openstack_janitor.detectors.images import OldUnusedImagesDetector

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
OLD = "2026-01-01T00:00:00Z"  # ~273 days before NOW
RECENT = "2026-09-01T00:00:00Z"  # ~30 days before NOW


@pytest.fixture
def old_image(fake_image):
    """An image that is flagged unless a test overrides something."""

    def _make(**overrides: Any) -> SimpleNamespace:
        defaults: dict[str, Any] = {
            "visibility": "private",
            "status": "active",
            "is_protected": False,
            "created_at": OLD,
        }
        defaults.update(overrides)
        return fake_image(**defaults)

    return _make


def _detect(conn) -> list:
    return OldUnusedImagesDetector(now=NOW).detect(conn)


def test_flags_old_unused_private_image(fake_conn, old_image) -> None:
    img = old_image()
    fake_conn.image.images.return_value = [img]

    findings = _detect(fake_conn)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.resource_type == "image"
    assert finding.resource_id == img.id
    assert finding.resource_name == img.name
    assert finding.project_id == img.owner
    assert "273 days old" in finding.reason
    assert "threshold 180" in finding.reason
    assert finding.extra == {"created_at": OLD, "visibility": "private", "status": "active"}
    assert finding.created_at == OLD


def test_ignores_image_younger_than_threshold(fake_conn, old_image) -> None:
    fake_conn.image.images.return_value = [old_image(created_at=RECENT)]

    assert _detect(fake_conn) == []


def test_threshold_is_configurable(fake_conn, old_image) -> None:
    fake_conn.image.images.return_value = [old_image(created_at=RECENT)]

    findings = OldUnusedImagesDetector(max_age_days=7, now=NOW).detect(fake_conn)

    assert len(findings) == 1


@pytest.mark.parametrize("created_at", [None, "", "not-a-date"])
def test_never_flags_undatable_image(fake_conn, old_image, created_at) -> None:
    fake_conn.image.images.return_value = [old_image(created_at=created_at)]

    assert _detect(fake_conn) == []


@pytest.mark.parametrize("visibility", ["public", "community", None, "bogus"])
def test_ignores_non_project_scoped_images(fake_conn, old_image, visibility) -> None:
    fake_conn.image.images.return_value = [old_image(visibility=visibility)]

    assert _detect(fake_conn) == []


def test_ignores_protected_image(fake_conn, old_image) -> None:
    fake_conn.image.images.return_value = [old_image(is_protected=True)]

    assert _detect(fake_conn) == []


@pytest.mark.parametrize("status", ["deleted", "pending_delete"])
def test_ignores_image_already_being_deleted(fake_conn, old_image, status) -> None:
    fake_conn.image.images.return_value = [old_image(status=status)]

    assert _detect(fake_conn) == []


@pytest.mark.parametrize(
    "server_image",
    [
        SimpleNamespace(id="img-0001"),  # openstacksdk Image resource
        {"id": "img-0001"},  # raw API dict
    ],
)
def test_ignores_image_a_server_boots_from(fake_conn, old_image, fake_server, server_image) -> None:
    fake_conn.image.images.return_value = [old_image()]
    fake_conn.compute.servers.return_value = [fake_server(status="ACTIVE", image=server_image)]

    assert _detect(fake_conn) == []


def test_volume_backed_server_uses_no_image(fake_conn, old_image, fake_server) -> None:
    fake_conn.image.images.return_value = [old_image()]
    fake_conn.compute.servers.return_value = [fake_server(status="ACTIVE", image="")]

    assert len(_detect(fake_conn)) == 1


@pytest.mark.parametrize("status", ["SHELVED", "SHELVED_OFFLOADED"])
def test_ignores_shelve_snapshot_of_shelved_server(
    fake_conn, old_image, fake_server, status
) -> None:
    img = old_image(instance_uuid="srv-0001")
    fake_conn.image.images.return_value = [img]
    fake_conn.compute.servers.return_value = [
        fake_server(id="srv-0001", status=status, image={"id": "img-base"})
    ]

    assert _detect(fake_conn) == []


def test_flags_snapshot_of_server_that_is_not_shelved(fake_conn, old_image, fake_server) -> None:
    img = old_image(instance_uuid="srv-0001")
    fake_conn.image.images.return_value = [img]
    fake_conn.compute.servers.return_value = [
        fake_server(id="srv-0001", status="ACTIVE", image={"id": "img-base"})
    ]

    assert len(_detect(fake_conn)) == 1


def test_reads_instance_uuid_from_properties(fake_conn, old_image, fake_server) -> None:
    img = old_image(properties={"instance_uuid": "srv-0001"})
    fake_conn.image.images.return_value = [img]
    fake_conn.compute.servers.return_value = [
        fake_server(id="srv-0001", status="SHELVED_OFFLOADED", image="")
    ]

    assert _detect(fake_conn) == []


@pytest.mark.parametrize("key", ["kernel_id", "ramdisk_id"])
def test_ignores_kernel_and_ramdisk_of_another_image(fake_conn, old_image, key) -> None:
    kernel = old_image(id="img-aki")
    machine = old_image(id="img-ami", visibility="public", **{key: "img-aki"})
    fake_conn.image.images.return_value = [kernel, machine]

    assert _detect(fake_conn) == []


def test_flags_shared_image_when_all_projects_listed(fake_conn, old_image) -> None:
    fake_conn.image.images.return_value = [old_image(visibility="shared")]

    findings = _detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].extra["visibility"] == "shared"


def test_skips_shared_image_when_server_list_is_project_scoped(
    fake_conn, old_image, fake_server
) -> None:
    private = old_image(id="img-private")
    shared = old_image(id="img-shared", visibility="shared")
    fake_conn.image.images.return_value = [private, shared]

    def servers_side_effect(*args, **kwargs):
        if kwargs.get("all_projects"):
            raise ForbiddenException("admin only")
        return [fake_server(status="ACTIVE", image="")]

    fake_conn.compute.servers.side_effect = servers_side_effect

    findings = _detect(fake_conn)

    assert [f.resource_id for f in findings] == ["img-private"]


def test_includes_hidden_images(fake_conn, old_image) -> None:
    hidden = old_image(id="img-hidden", is_hidden=True)

    def images_side_effect(*args, **kwargs):
        return [hidden] if kwargs.get("is_hidden") else []

    fake_conn.image.images.side_effect = images_side_effect

    findings = _detect(fake_conn)

    assert [f.resource_id for f in findings] == ["img-hidden"]


def test_reports_snapshots_left_behind_by_volume_backed_image(fake_conn, old_image) -> None:
    bdm = json.dumps([{"source_type": "snapshot", "snapshot_id": "snap-0001"}])
    fake_conn.image.images.return_value = [old_image(properties={"block_device_mapping": bdm})]

    findings = _detect(fake_conn)

    assert findings[0].extra["snapshot_ids"] == "snap-0001"


def test_stamps_keep_marker_from_image_properties(fake_conn, old_image) -> None:
    fake_conn.image.images.return_value = [old_image(properties={"janitor:keep": "yes"})]

    findings = _detect(fake_conn)

    assert "janitor:keep" in findings[0].markers


def test_clean_deletes_image(fake_conn, old_image) -> None:
    fake_conn.image.images.return_value = [old_image()]
    detector = OldUnusedImagesDetector(now=NOW)
    finding = detector.detect(fake_conn)[0]

    detector.clean(fake_conn, finding)

    fake_conn.image.delete_image.assert_called_once_with("img-0001", ignore_missing=True)
