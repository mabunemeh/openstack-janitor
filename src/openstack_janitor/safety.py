"""Safety-rail helpers: keep-marker collection and creation-timestamp lookup.

Detectors stamp these facts onto each `Finding` at detect time (see
`Finding.markers` / `Finding.created_at`), rather than `clean` re-fetching
the resource later. Re-fetching would cost an extra API call per finding
and could disagree with the plan the user already confirmed -- the printed
plan must be what gets deleted. So detectors record the raw facts here, and
`clean` applies policy (keep marker, minimum age) against those recorded
facts.
"""

from __future__ import annotations

from typing import Any

KEEP_MARKER_DEFAULT = "janitor:keep"


def resource_markers(resource: Any) -> tuple[str, ...]:
    """Collect every label-ish string attached to `resource`.

    Union of:

    - `resource.tags` -- a list/iterable of strings (Neutron ports/FIPs/
      security groups, Nova servers, Glance images). Non-string items are
      skipped defensively.
    - keys of `resource.metadata`, when it is a dict (Cinder volumes/
      snapshots, Nova servers).
    - keys of `resource.properties`, when it is a dict (Glance images).

    Returned as a sorted, de-duplicated tuple -- MUST be a tuple, not a
    set/frozenset: `Finding` is serialized with `dataclasses.asdict()` +
    `json.dumps()` for `--format json`, and `json.dumps` raises `TypeError`
    on a bare set.

    Never raises: an unexpected shape on any of these fields is ignored
    rather than propagated, since a malformed attribute on one resource
    must not break scanning every other resource.
    """
    markers: set[str] = set()

    tags = getattr(resource, "tags", None)
    # A bare str/bytes is iterable but iterates character-wise (or byte-wise),
    # which would silently scatter a marker like "janitor:keep" into single
    # characters instead of matching it -- openstacksdk always returns a
    # list here, so this is defensive only, but this module's only job is
    # to stop deletions, so it must not be fooled by the wrong shape.
    if tags is not None and not isinstance(tags, (str, bytes)):
        try:
            for tag in tags:
                if isinstance(tag, str):
                    markers.add(tag)
        except TypeError:
            pass

    metadata = getattr(resource, "metadata", None)
    if isinstance(metadata, dict):
        markers.update(key for key in metadata if isinstance(key, str))

    properties = getattr(resource, "properties", None)
    if isinstance(properties, dict):
        markers.update(key for key in properties if isinstance(key, str))

    return tuple(sorted(markers))


def resource_created_at(resource: Any) -> str:
    """Return `resource.created_at` as a string, or "" when absent.

    Nearly every OpenStack resource carries a `created_at` timestamp
    (Neutron standard attributes, Cinder, Nova, Glance), so this is a
    single, resource-agnostic hook for the min-age safety rail.
    """
    return str(getattr(resource, "created_at", "") or "")


def safety_fields(resource: Any) -> dict[str, Any]:
    """Bundle `resource_markers` and `resource_created_at` for splatting into a Finding."""
    return {"markers": resource_markers(resource), "created_at": resource_created_at(resource)}


__all__ = ["KEEP_MARKER_DEFAULT", "resource_created_at", "resource_markers", "safety_fields"]
