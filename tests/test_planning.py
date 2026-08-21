"""Tests for the pure clean-plan classification (the safety rails).

These exercise :func:`plan_status` directly, without driving the CLI: the
precedence between --exclude, the keep marker, the min-age floor, and detector
support is the code most deserving of focused unit tests, since a mistake here
is a mistake about deleting real infrastructure. The end-to-end wiring through
`janitor clean` is covered separately in test_clean.py.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import ClassVar

from openstack_janitor.detectors.base import Detector, Finding
from openstack_janitor.planning import (
    EXCLUDED,
    PROTECTED,
    TOO_NEW,
    UNSUPPORTED,
    WOULD_DELETE,
    plan_status,
    supports_clean,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class _CleanableDetector(Detector):
    name: ClassVar[str] = "cleanable"
    description: ClassVar[str] = "supports clean"

    def detect(self, conn):  # pragma: no cover - not exercised here
        return []

    def clean(self, conn, finding) -> None:  # pragma: no cover - not called
        pass


class _AuditOnlyDetector(Detector):
    name: ClassVar[str] = "audit-only"
    description: ClassVar[str] = "inherits the base clean stub"

    def detect(self, conn):  # pragma: no cover - not exercised here
        return []


def _finding(
    *,
    resource_id: str = "res-1",
    markers: tuple[str, ...] = (),
    created_at: str = "",
) -> Finding:
    return Finding(
        resource_type="volume",
        resource_id=resource_id,
        resource_name="name",
        project_id="proj-1",
        reason="unattached",
        markers=markers,
        created_at=created_at,
    )


def _status(
    finding: Finding,
    det: Detector,
    *,
    exclude_ids: set[str] | None = None,
    keep_marker: str = "janitor:keep",
    min_age_days: float = 0.0,
    now: datetime = NOW,
) -> str:
    return plan_status(
        finding,
        det,
        exclude_ids=exclude_ids or set(),
        keep_marker=keep_marker,
        min_age_days=min_age_days,
        now=now,
    )


# --- supports_clean ---------------------------------------------------------


def test_supports_clean_true_for_overriding_detector() -> None:
    assert supports_clean(_CleanableDetector()) is True


def test_supports_clean_false_for_audit_only_detector() -> None:
    assert supports_clean(_AuditOnlyDetector()) is False


def test_supports_clean_true_for_per_instance_assignment() -> None:
    """A `det.clean = fn` override must count as supported: previewing
    'unsupported' for something --yes would really delete is the dangerous
    direction to be wrong in."""
    det = _AuditOnlyDetector()
    det.clean = lambda conn, finding: None  # type: ignore[method-assign]

    assert supports_clean(det) is True


# --- baseline ---------------------------------------------------------------


def test_would_delete_when_no_rail_applies() -> None:
    assert _status(_finding(), _CleanableDetector()) == WOULD_DELETE


def test_unsupported_when_detector_cannot_clean() -> None:
    assert _status(_finding(), _AuditOnlyDetector()) == UNSUPPORTED


# --- exclude ----------------------------------------------------------------


def test_excluded_id_is_skipped() -> None:
    finding = _finding(resource_id="keep-me")

    assert _status(finding, _CleanableDetector(), exclude_ids={"keep-me"}) == EXCLUDED


# --- keep marker ------------------------------------------------------------


def test_keep_marker_protects() -> None:
    finding = _finding(markers=("janitor:keep",))

    assert _status(finding, _CleanableDetector()) == PROTECTED


def test_keep_marker_match_is_exact() -> None:
    """A near-miss marker must NOT protect: the match is case- and
    whitespace-sensitive, so protection cannot be accidentally implied."""
    finding = _finding(markers=("janitor:keep ", "Janitor:Keep"))

    assert _status(finding, _CleanableDetector()) == WOULD_DELETE


def test_configurable_keep_marker() -> None:
    finding = _finding(markers=("do-not-delete",))

    assert _status(finding, _CleanableDetector(), keep_marker="do-not-delete") == PROTECTED


# --- min-age floor ----------------------------------------------------------


def test_too_new_when_younger_than_floor() -> None:
    finding = _finding(created_at=(NOW - timedelta(days=2)).isoformat())

    assert _status(finding, _CleanableDetector(), min_age_days=7) == TOO_NEW


def test_old_enough_passes_the_floor() -> None:
    finding = _finding(created_at=(NOW - timedelta(days=30)).isoformat())

    assert _status(finding, _CleanableDetector(), min_age_days=7) == WOULD_DELETE


def test_undatable_is_too_new_when_floor_active() -> None:
    """Fail closed: what cannot be dated cannot be proven old enough."""
    finding = _finding(created_at="")

    assert _status(finding, _CleanableDetector(), min_age_days=7) == TOO_NEW


def test_undatable_is_not_blocked_when_floor_disabled() -> None:
    finding = _finding(created_at="")

    assert _status(finding, _CleanableDetector(), min_age_days=0) == WOULD_DELETE


# --- precedence -------------------------------------------------------------


def test_exclude_beats_keep_marker() -> None:
    finding = _finding(resource_id="keep-me", markers=("janitor:keep",))

    assert _status(finding, _CleanableDetector(), exclude_ids={"keep-me"}) == EXCLUDED


def test_keep_marker_beats_min_age() -> None:
    """A protected resource is reported protected, not too-new, even when it
    would also fail the floor."""
    finding = _finding(
        markers=("janitor:keep",),
        created_at=(NOW - timedelta(days=1)).isoformat(),
    )

    assert _status(finding, _CleanableDetector(), min_age_days=7) == PROTECTED


def test_min_age_beats_detector_support() -> None:
    """A too-new resource is reported too-new before the detector's inability
    to clean is even considered."""
    finding = _finding(created_at=(NOW - timedelta(days=1)).isoformat())

    assert _status(finding, _AuditOnlyDetector(), min_age_days=7) == TOO_NEW
