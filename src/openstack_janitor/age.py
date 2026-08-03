"""Shared timestamp-age helper.

Used by age-based detectors (old snapshots, shutoff instances, ...) and also
backs the min-age safety rail that gates any destructive "clean" action
behind a minimum resource age.
"""

from __future__ import annotations

from datetime import datetime, timezone


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
        # The "Z" -> "+00:00" swap is REQUIRED (not just belt-and-braces) on
        # Python < 3.11: datetime.fromisoformat() there cannot parse a
        # trailing "Z" at all and raises ValueError.
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    reference = now if now is not None else datetime.now(timezone.utc)

    return (reference - parsed).total_seconds() / 86400
