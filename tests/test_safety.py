"""Tests for the keep-marker / created_at safety-rail helpers."""

from __future__ import annotations

import dataclasses
import json
from types import SimpleNamespace

from openstack_janitor.detectors.base import Finding
from openstack_janitor.safety import (
    KEEP_MARKER_DEFAULT,
    resource_created_at,
    resource_markers,
    safety_fields,
)


def test_finds_marker_in_tags() -> None:
    resource = SimpleNamespace(tags=["janitor:keep", "other-tag"])

    assert resource_markers(resource) == ("janitor:keep", "other-tag")


def test_finds_marker_in_metadata_keys() -> None:
    resource = SimpleNamespace(metadata={"janitor:keep": "true", "owner": "team-a"})

    assert resource_markers(resource) == ("janitor:keep", "owner")


def test_finds_marker_in_properties_keys() -> None:
    resource = SimpleNamespace(properties={"janitor:keep": "1"})

    assert resource_markers(resource) == ("janitor:keep",)


def test_markers_are_deduped_and_sorted_across_sources() -> None:
    resource = SimpleNamespace(
        tags=["zeta", "janitor:keep"],
        metadata={"janitor:keep": "true", "alpha": "x"},
        properties={"beta": "y"},
    )

    assert resource_markers(resource) == ("alpha", "beta", "janitor:keep", "zeta")


def test_markers_return_type_is_a_tuple() -> None:
    """MUST be a tuple, not a set: dataclasses.asdict + json.dumps requires it."""
    resource = SimpleNamespace(tags=["janitor:keep"])

    result = resource_markers(resource)

    assert isinstance(result, tuple)


def test_markers_ignore_non_string_tag_items() -> None:
    resource = SimpleNamespace(tags=["ok-tag", 123, None, ["nested"]])

    assert resource_markers(resource) == ("ok-tag",)


def test_markers_ignore_non_dict_metadata() -> None:
    resource = SimpleNamespace(tags=[], metadata="not-a-dict")

    assert resource_markers(resource) == ()


def test_markers_ignore_non_dict_properties() -> None:
    resource = SimpleNamespace(tags=[], properties=["not", "a", "dict"])

    assert resource_markers(resource) == ()


def test_markers_missing_attributes_return_empty_tuple() -> None:
    resource = SimpleNamespace(id="x")

    assert resource_markers(resource) == ()


def test_markers_never_raises_on_unexpected_tag_shape() -> None:
    resource = SimpleNamespace(tags=42)

    assert resource_markers(resource) == ()


def test_markers_ignore_bare_string_tags_instead_of_iterating_characters() -> None:
    """A bare str is iterable but iterates character-wise, which would
    silently scatter "janitor:keep" into single-character "markers" and
    lose protection entirely. openstacksdk always returns a list here, but
    this module's only job is to stop deletions."""
    resource = SimpleNamespace(tags="janitor:keep")

    assert resource_markers(resource) == ()


def test_markers_ignore_bare_bytes_tags() -> None:
    resource = SimpleNamespace(tags=b"janitor:keep")

    assert resource_markers(resource) == ()


def test_created_at_present() -> None:
    resource = SimpleNamespace(created_at="2026-01-01T00:00:00Z")

    assert resource_created_at(resource) == "2026-01-01T00:00:00Z"


def test_created_at_missing_returns_empty_string() -> None:
    resource = SimpleNamespace(id="x")

    assert resource_created_at(resource) == ""


def test_created_at_none_returns_empty_string() -> None:
    resource = SimpleNamespace(created_at=None)

    assert resource_created_at(resource) == ""


def test_safety_fields_bundles_both() -> None:
    resource = SimpleNamespace(tags=["janitor:keep"], created_at="2026-01-01T00:00:00Z")

    fields = safety_fields(resource)

    assert fields == {"markers": ("janitor:keep",), "created_at": "2026-01-01T00:00:00Z"}


def test_keep_marker_default_value() -> None:
    assert KEEP_MARKER_DEFAULT == "janitor:keep"


def test_finding_with_markers_is_json_serializable_and_round_trips_as_list() -> None:
    """Regression test: markers as a bare set would raise TypeError here."""
    finding = Finding(
        resource_type="port",
        resource_id="port-0001",
        resource_name="test-port",
        project_id="project-0001",
        reason="port has no device owner or device id",
        markers=("janitor:keep", "team-a"),
        created_at="2026-01-01T00:00:00Z",
    )

    # Same path as `--format json`: reporting.render_json does
    # json.dumps([dataclasses.asdict(f) for f in findings], ...).
    rendered = json.dumps(dataclasses.asdict(finding))
    data = json.loads(rendered)

    assert data["markers"] == ["janitor:keep", "team-a"]
    assert isinstance(data["markers"], list)
