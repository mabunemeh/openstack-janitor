"""Tests for the unattached-volumes detector."""

from __future__ import annotations

from openstack.exceptions import ForbiddenException

from openstack_janitor.detectors.volumes import UnattachedVolumesDetector
from tests.conftest import fake_volume


def test_finds_unattached_available_volume(fake_conn) -> None:
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


def test_ignores_in_use_volume_with_attachments(fake_conn) -> None:
    vol = fake_volume(status="in-use", attachments=[{"server_id": "srv-1"}])
    fake_conn.block_storage.volumes.return_value = [vol]

    findings = UnattachedVolumesDetector().detect(fake_conn)

    assert findings == []


def test_ignores_available_but_attached_edge_case(fake_conn) -> None:
    # Defensive: a volume reporting "available" status but with a stale/leftover
    # attachment record should not be flagged as an orphan.
    vol = fake_volume(status="available", attachments=[{"server_id": "srv-1"}])
    fake_conn.block_storage.volumes.return_value = [vol]

    findings = UnattachedVolumesDetector().detect(fake_conn)

    assert findings == []


def test_falls_back_when_all_projects_forbidden(fake_conn) -> None:
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


def test_name_none_is_handled(fake_conn) -> None:
    vol = fake_volume(status="available", attachments=[], name=None)
    fake_conn.block_storage.volumes.return_value = [vol]

    findings = UnattachedVolumesDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].resource_name == ""
