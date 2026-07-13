"""Shared timestamp-age helper.

Used by age-based detectors (old snapshots, shutoff instances, ...) and will
also back the future min-age safety rail that gates any destructive "clean"
action behind a minimum resource age.
"""

from __future__ import annotations

from datetime import UTC, datetime


def age_in_days(timestamp: str | None, *, now: datetime | None = None) -> float | None:
    """Return the age of an ISO 8601 ``timestamp`` in days, or ``None``.

    ``timestamp`` is expected in the form openstacksdk returns resource
    timestamps in, e.g. ``"2026-06-01T12:00:00Z"``, with or without
    microseconds, or with a ``+00:00``-style offset. Naive timestamps (no
    offset at all) are treated as UTC, since openstacksdk sometimes returns
    naive UTC strings.

    Returns ``None`` if ``timestamp`` is ``None`` or cannot be parsed. Never
    raises.

    :param timestamp: ISO 8601 timestamp string, or ``None``.
    :param now: Reference time to compute age against. Defaults to the
        current UTC time; injectable for tests.
    """
    if timestamp is None:
        return None

    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)

    reference = now if now is not None else datetime.now(UTC)

    return (reference - parsed).total_seconds() / 86400
