"""Base types shared by all detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

from openstack.connection import Connection


@dataclass(frozen=True)
class Finding:
    """A single flagged resource."""

    resource_type: str
    resource_id: str
    resource_name: str
    project_id: str
    reason: str
    extra: dict[str, str] = field(default_factory=dict)
    detector: str = ""
    """Kebab-case detector name that flagged this resource (set by audit)."""


class Detector(ABC):
    """A check that scans a cloud for one category of orphaned/wasteful resource."""

    name: ClassVar[str]
    """Kebab-case identifier, e.g. "unattached-volumes"."""

    description: ClassVar[str]
    """Short human-readable description of what this detector looks for."""

    @abstractmethod
    def detect(self, conn: Connection) -> list[Finding]:
        """Scan the cloud reachable via ``conn`` and return any findings."""
        raise NotImplementedError

    def clean(self, conn: Connection, finding: Finding) -> None:
        """Delete the resource named by `finding`.

        Implementations must be idempotent (ignore an already-missing
        resource) and must raise on real failures so the CLI can report them.

        Deliberately concrete rather than abstract: a detector may be
        audit-only (deletion unsafe or undefined for its resource), and
        subclasses written outside this repo must not break just because
        `clean` arrived. Not overriding it means `janitor clean` reports the
        resource as unsupported instead of deleting it.
        """
        raise NotImplementedError(f"{type(self).__name__} does not support clean")
