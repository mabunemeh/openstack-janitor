"""Detector registry.

This list is deliberately explicit and boring: to add a detector, write the
class and append it here. ``get_detectors`` optionally takes a
``janitor.toml`` :class:`~openstack_janitor.config.Config` to disable
detectors and override their constructor options.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from openstack_janitor.detectors.base import Detector, Finding
from openstack_janitor.detectors.floating_ips import UnassociatedFloatingIpsDetector
from openstack_janitor.detectors.images import OrphanSnapshotImagesDetector
from openstack_janitor.detectors.instances import ShutoffInstancesDetector
from openstack_janitor.detectors.ports import OrphanedPortsDetector
from openstack_janitor.detectors.security_groups import UnusedSecurityGroupsDetector
from openstack_janitor.detectors.snapshots import OldSnapshotsDetector
from openstack_janitor.detectors.volumes import UnattachedVolumesDetector

if TYPE_CHECKING:
    # Deferred to avoid a circular import: config.py imports this module (to
    # validate against ALL_DETECTORS), so this module must not import config
    # at runtime. Safe as a type-only import under `from __future__ import
    # annotations`.
    from openstack_janitor.config import Config

ALL_DETECTORS: list[type[Detector]] = [
    UnattachedVolumesDetector,
    UnassociatedFloatingIpsDetector,
    OrphanedPortsDetector,
    OldSnapshotsDetector,
    ShutoffInstancesDetector,
    UnusedSecurityGroupsDetector,
    OrphanSnapshotImagesDetector,
]


def get_detectors(config: Config | None = None) -> list[Detector]:
    """Instantiate every registered detector, honoring an optional Config.

    ``config=None`` preserves the original behavior: every detector, default
    options. With a config, detectors whose name is in ``config.disabled``
    are omitted, and the rest are instantiated with
    ``config.detector_options.get(name, {})`` as constructor kwargs.
    """
    if config is None:
        return [detector_cls() for detector_cls in ALL_DETECTORS]
    return [
        detector_cls(**config.detector_options.get(detector_cls.name, {}))
        for detector_cls in ALL_DETECTORS
        if detector_cls.name not in config.disabled
    ]


__all__ = ["ALL_DETECTORS", "Detector", "Finding", "get_detectors"]
