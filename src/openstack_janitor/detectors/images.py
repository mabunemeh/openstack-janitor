"""Detectors for Glance images: orphaned snapshot-backed images and old unused images."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, ClassVar

from openstack.connection import Connection
from openstack.exceptions import ForbiddenException, NotFoundException

from openstack_janitor.age import age_in_days
from openstack_janitor.detectors.base import Detector, Finding
from openstack_janitor.safety import safety_fields

_BDM_PROPERTY_KEYS = ("block_device_mapping", "img_block_device_mapping")


def _snapshot_ids_from_bdm(block_device_mapping: Any) -> list[str] | None:
    """Extract snapshot ids from a Glance BDM property value.

    Returns ``None`` when the value is missing, empty, or unparseable — the
    caller should skip that property. Returns a (possibly empty) list of
    snapshot ids when the BDM is a valid JSON array / list.

    Entries are collected when ``snapshot_id`` is set and ``source_type`` is
    either ``"snapshot"`` or omitted (legacy Nova/Glance BDM metadata).
    """
    if block_device_mapping is None or block_device_mapping == "":
        return None

    if isinstance(block_device_mapping, str):
        try:
            parsed = json.loads(block_device_mapping)
        except (json.JSONDecodeError, TypeError):
            return None
    else:
        parsed = block_device_mapping

    if not isinstance(parsed, list):
        return None

    snapshot_ids: list[str] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        snapshot_id = entry.get("snapshot_id")
        if not snapshot_id:
            continue
        # Accept explicit snapshot source, or legacy entries that omit source_type.
        source_type = entry.get("source_type")
        if source_type not in (None, "", "snapshot"):
            continue
        snapshot_ids.append(str(snapshot_id))
    return snapshot_ids


def _snapshot_ids_from_properties(props: dict[str, Any]) -> list[str] | None:
    """Collect snapshot ids from either Glance BDM property key."""
    collected: list[str] = []
    found_valid = False
    for key in _BDM_PROPERTY_KEYS:
        if key not in props:
            continue
        ids = _snapshot_ids_from_bdm(props[key])
        if ids is None:
            continue
        found_valid = True
        for sid in ids:
            if sid not in collected:
                collected.append(sid)
    return collected if found_valid else None


def _list_images(conn: Connection) -> list[Any]:
    """List visible and hidden images, deduplicated by id."""
    # Glance omits hidden images unless os_hidden=true is requested, and
    # os_hidden=true returns *only* hidden images — so both calls are needed.
    seen: set[str] = set()
    images: list[Any] = []
    for image in list(conn.image.images()) + list(conn.image.images(is_hidden=True)):
        image_id = getattr(image, "id", None)
        if not image_id or image_id in seen:
            continue
        seen.add(image_id)
        images.append(image)
    return images


def _list_snapshot_ids(conn: Connection) -> tuple[set[str], bool]:
    """Return ``(ids, complete)``.

    ``complete`` is True when the admin ``all_projects`` list succeeded, so
    absence from ``ids`` means the snapshot is gone. When False, the list is
    project-scoped and absences must be confirmed with ``get_snapshot`` to
    avoid false positives on shared/public images from other tenants.
    """
    try:
        snapshots = list(conn.block_storage.snapshots(details=True, all_projects=True))
        return {snap.id for snap in snapshots}, True
    except ForbiddenException:
        # all_projects=True requires admin; fall back to the caller's own project.
        snapshots = list(conn.block_storage.snapshots(details=True))
        return {snap.id for snap in snapshots}, False


def _missing_snapshot_ids(
    conn: Connection,
    snapshot_ids: list[str],
    known: set[str],
    *,
    complete: bool,
) -> list[str]:
    """Return snapshot ids confirmed missing; skip unknowns when list is incomplete."""
    missing: list[str] = []
    for sid in snapshot_ids:
        if sid in known:
            continue
        if complete:
            missing.append(sid)
            continue
        # Project-scoped list: confirm via get before treating as orphan.
        try:
            conn.block_storage.get_snapshot(sid)
        except NotFoundException:
            missing.append(sid)
        except ForbiddenException:
            # Visible image, inaccessible foreign snapshot — under-report.
            continue
    return missing


class OrphanSnapshotImagesDetector(Detector):
    """Flags Glance images that reference Cinder snapshots which no longer exist."""

    name: ClassVar[str] = "orphan-snapshot-images"
    description: ClassVar[str] = (
        "Images based on volume snapshots whose backing snapshot no longer exists"
    )

    def detect(self, conn: Connection) -> list[Finding]:
        images = _list_images(conn)
        known, complete = _list_snapshot_ids(conn)

        findings: list[Finding] = []
        for image in images:
            props = getattr(image, "properties", None) or {}
            if not isinstance(props, dict):
                props = {}
            snapshot_ids = _snapshot_ids_from_properties(props)
            if snapshot_ids is None or not snapshot_ids:
                continue

            missing = _missing_snapshot_ids(conn, snapshot_ids, known, complete=complete)
            if not missing:
                continue

            extra: dict[str, str] = {
                "missing_snapshot_ids": ",".join(missing),
            }
            is_hidden = getattr(image, "is_hidden", None)
            if is_hidden is None:
                is_hidden = props.get("os_hidden")
            if is_hidden:
                extra["os_hidden"] = "true"

            findings.append(
                Finding(
                    resource_type="image",
                    resource_id=image.id,
                    resource_name=getattr(image, "name", "") or "",
                    project_id=getattr(image, "owner", "") or "",
                    reason=f"image references missing snapshot(s): {', '.join(missing)}",
                    extra=extra,
                    **safety_fields(image),
                )
            )
        return findings

    def clean(self, conn: Connection, finding: Finding) -> None:
        conn.image.delete_image(finding.resource_id, ignore_missing=True)


# Only images scoped to a project are candidates. Public and community images
# are catalog images published for others to boot from; an image with no (or
# an unrecognised) visibility is skipped rather than guessed at.
_CANDIDATE_VISIBILITIES = ("private", "shared")
# Shelving snapshots the server into an image, and unshelving boots from it:
# deleting that image destroys the shelved server's disk for good.
_SHELVED_STATUSES = ("SHELVED", "SHELVED_OFFLOADED")
_GONE_IMAGE_STATUSES = ("deleted", "pending_delete")


def _image_field(image: Any, key: str) -> Any:
    """Read ``key`` as an image attribute, falling back to its ``properties``."""
    value = getattr(image, key, None)
    if value is None:
        props = getattr(image, "properties", None)
        if isinstance(props, dict):
            value = props.get(key)
    return value


def _server_image_id(server: Any) -> str | None:
    """Return the id of the image ``server`` booted from, if any.

    openstacksdk gives an ``Image`` resource; the raw API gives a dict, or
    ``""`` for a volume-backed server.
    """
    image = getattr(server, "image", None)
    image_id = image.get("id") if isinstance(image, dict) else getattr(image, "id", None)
    return str(image_id) if image_id else None


def _list_servers(conn: Connection) -> tuple[list[Any], bool]:
    """Return ``(servers, complete)``.

    ``complete`` is True when the admin ``all_projects`` list succeeded. When
    False only the caller's project is visible, so a server in another
    project could still be using a shared image.
    """
    try:
        return list(conn.compute.servers(details=True, all_projects=True)), True
    except ForbiddenException:
        # all_projects=True requires admin; fall back to the caller's own project.
        return list(conn.compute.servers(details=True)), False


class OldUnusedImagesDetector(Detector):
    """Flags private/shared images older than a threshold that nothing uses.

    An image counts as in use, and is never flagged, when it is:

    - the boot image of any server visible to the caller;
    - the shelve snapshot of a shelved server (its ``instance_uuid``);
    - the ``kernel_id`` / ``ramdisk_id`` of another image.

    Public and community images are never flagged, nor are protected images
    (Glance refuses to delete them). Shared images are only flagged when the
    server list covers every project; otherwise another project could be
    booting from them unseen. Volumes created from an image do not count as
    using it: Cinder keeps its own copy.
    """

    name: ClassVar[str] = "old-unused-images"
    description: ClassVar[str] = (
        "Private/shared images older than a threshold that no server or image uses"
    )

    def __init__(self, max_age_days: float = 180.0, *, now: datetime | None = None) -> None:
        self.max_age_days = max_age_days
        self.now = now

    def detect(self, conn: Connection) -> list[Finding]:
        images = _list_images(conn)
        servers, complete = _list_servers(conn)

        in_use: set[str] = set()
        shelved_server_ids: set[str] = set()
        for server in servers:
            image_id = _server_image_id(server)
            if image_id:
                in_use.add(image_id)
            if getattr(server, "status", None) in _SHELVED_STATUSES:
                shelved_server_ids.add(server.id)
        for image in images:
            for key in ("kernel_id", "ramdisk_id"):
                ref = _image_field(image, key)
                if ref:
                    in_use.add(str(ref))

        findings: list[Finding] = []
        for image in images:
            visibility = getattr(image, "visibility", None)
            if visibility not in _CANDIDATE_VISIBILITIES:
                continue
            if visibility == "shared" and not complete:
                continue
            if getattr(image, "is_protected", False):
                continue
            if getattr(image, "status", None) in _GONE_IMAGE_STATUSES:
                continue
            if image.id in in_use:
                continue
            if _image_field(image, "instance_uuid") in shelved_server_ids:
                continue

            # Never flag what we can't date -- a missing/unparsable created_at
            # is skipped silently rather than guessed at.
            age = age_in_days(getattr(image, "created_at", None), now=self.now)
            if age is None or age <= self.max_age_days:
                continue

            extra: dict[str, str] = {
                "created_at": str(image.created_at),
                "visibility": str(visibility),
            }
            status = getattr(image, "status", None)
            if status:
                extra["status"] = str(status)
            props = getattr(image, "properties", None)
            snapshot_ids = _snapshot_ids_from_properties(props if isinstance(props, dict) else {})
            if snapshot_ids:
                # Deleting the image leaves these volume snapshots behind.
                extra["snapshot_ids"] = ",".join(snapshot_ids)

            findings.append(
                Finding(
                    resource_type="image",
                    resource_id=image.id,
                    resource_name=getattr(image, "name", "") or "",
                    project_id=getattr(image, "owner", "") or "",
                    reason=(
                        f"image is {age:.0f} days old (threshold {self.max_age_days:.0f}) "
                        "and no server or image uses it"
                    ),
                    extra=extra,
                    **safety_fields(image),
                )
            )
        return findings

    def clean(self, conn: Connection, finding: Finding) -> None:
        conn.image.delete_image(finding.resource_id, ignore_missing=True)
