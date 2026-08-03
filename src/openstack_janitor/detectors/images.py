"""Detector for images whose backing volume snapshots no longer exist."""

from __future__ import annotations

import json
from typing import Any, ClassVar

from openstack.connection import Connection
from openstack.exceptions import ForbiddenException, NotFoundException

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
