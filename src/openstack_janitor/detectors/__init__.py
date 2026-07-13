"""Detector registry.

This list is deliberately explicit and boring: to add a detector, write the
class and append it here. A config-driven enable/disable toggle (e.g. via
``janitor.toml``) arrives in a later change.
"""

from openstack_janitor.detectors.base import Detector, Finding
from openstack_janitor.detectors.floating_ips import UnassociatedFloatingIpsDetector
from openstack_janitor.detectors.instances import ShutoffInstancesDetector
from openstack_janitor.detectors.ports import OrphanedPortsDetector
from openstack_janitor.detectors.snapshots import OldSnapshotsDetector
from openstack_janitor.detectors.volumes import UnattachedVolumesDetector

ALL_DETECTORS: list[type[Detector]] = [
    UnattachedVolumesDetector,
    UnassociatedFloatingIpsDetector,
    OrphanedPortsDetector,
    OldSnapshotsDetector,
    ShutoffInstancesDetector,
]


def get_detectors() -> list[Detector]:
    """Instantiate every registered detector."""
    return [detector_cls() for detector_cls in ALL_DETECTORS]


__all__ = ["ALL_DETECTORS", "Detector", "Finding", "get_detectors"]
