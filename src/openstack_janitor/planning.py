"""Pure, cloud-free logic for deciding what ``janitor clean`` will do.

This module holds the safety-critical classification that decides, for each
finding, whether it will be deleted -- ``--exclude`` > keep marker > min-age
floor > detector support. It is deliberately free of Typer, rich, and any
cloud I/O so the rails can be unit-tested directly, without driving the whole
CLI: this is the code most deserving of focused tests, since a mistake here is
a mistake about deleting real infrastructure.

The CLI (:mod:`openstack_janitor.cli`) owns argument parsing, connecting,
detecting, printing, prompting, and the exit codes; it calls :func:`plan_status`
to build the preview and reuses the SAME ``now`` for the execute pass so the
printed plan is exactly what gets deleted.
"""

from __future__ import annotations

from datetime import datetime

from openstack_janitor.age import age_in_days
from openstack_janitor.detectors.base import Detector, Finding

# Terminal statuses a finding can be assigned before any deletion is attempted.
# "would-delete" is the only one that leads to an actual delete call; every
# other status is an intentional not-deleting outcome.
EXCLUDED = "skipped"
PROTECTED = "protected"
TOO_NEW = "too-new"
UNSUPPORTED = "unsupported"
WOULD_DELETE = "would-delete"


def supports_clean(det: Detector) -> bool:
    """Whether `det` defines deletion, i.e. does not inherit the base stub.

    Resolves per-instance assignment (``det.clean = fn``) as well as class-body
    overrides: previewing "unsupported" for something `--yes` would really
    delete is the dangerous direction to be wrong in.

    This reports whether `clean` is *defined*, not whether it will succeed -- a
    detector may override `clean` and still raise NotImplementedError, in which
    case the preview says "would-delete" and the execute reports "unsupported".
    """
    method = getattr(det.clean, "__func__", det.clean)
    return method is not Detector.clean


def plan_status(
    finding: Finding,
    det: Detector,
    *,
    exclude_ids: set[str],
    keep_marker: str,
    min_age_days: float,
    now: datetime,
) -> str:
    """Classify `finding` before any deletion is attempted.

    Precedence: ``--exclude`` > keep marker > min-age floor > detector
    support. The preview and execute loops both call this with the SAME
    `now`, captured once per invocation before the preview loop runs, so
    they can never disagree about which findings are eligible for deletion
    -- the printed plan is what gets deleted. Recomputing age against a
    fresh wall clock in the execute loop would let a resource that is
    "too-new" in the printed plan cross the floor while the user is
    reading it (or answering the confirmation prompt) and then get
    deleted -- exactly the outcome this rail exists to prevent.

    There is deliberately no way to bypass the keep marker here: the only
    way to unprotect a resource is to remove the marker from it in the
    cloud.
    """
    if finding.resource_id in exclude_ids:
        return EXCLUDED
    if keep_marker in finding.markers:
        return PROTECTED
    if min_age_days > 0:
        age = age_in_days(finding.created_at, now=now)
        # Fail closed: a resource we cannot date is never deleted once a
        # floor is active, rather than assuming it is old enough.
        if age is None or age < min_age_days:
            return TOO_NEW
    if not supports_clean(det):
        return UNSUPPORTED
    return WOULD_DELETE
