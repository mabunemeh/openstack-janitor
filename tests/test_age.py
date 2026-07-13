"""Tests for the age_in_days timestamp helper."""

from __future__ import annotations

from datetime import UTC, datetime

from openstack_janitor.age import age_in_days


def test_z_suffix_is_parsed() -> None:
    now = datetime(2026, 7, 13, tzinfo=UTC)
    assert age_in_days("2026-07-03T00:00:00Z", now=now) == 10.0


def test_offset_suffix_is_parsed() -> None:
    now = datetime(2026, 7, 13, tzinfo=UTC)
    assert age_in_days("2026-07-03T00:00:00+00:00", now=now) == 10.0


def test_non_utc_offset_is_normalized() -> None:
    # 2026-07-03T02:00:00+02:00 is 2026-07-03T00:00:00 UTC.
    now = datetime(2026, 7, 13, tzinfo=UTC)
    assert age_in_days("2026-07-03T02:00:00+02:00", now=now) == 10.0


def test_naive_string_treated_as_utc() -> None:
    now = datetime(2026, 7, 13, tzinfo=UTC)
    assert age_in_days("2026-07-03T00:00:00", now=now) == 10.0


def test_microseconds_variant_is_parsed() -> None:
    now = datetime(2026, 7, 13, tzinfo=UTC)
    result = age_in_days("2026-07-03T00:00:00.123456Z", now=now)
    assert result is not None
    assert round(result, 3) == 10.0


def test_none_returns_none() -> None:
    assert age_in_days(None) is None


def test_garbage_returns_none() -> None:
    assert age_in_days("not-a-timestamp") is None


def test_defaults_to_current_time_when_now_not_given() -> None:
    # Sanity check that the "now" default path doesn't raise; exact value is
    # not asserted since it depends on wall-clock time.
    result = age_in_days("2026-01-01T00:00:00Z")
    assert result is not None
    assert result > 0
