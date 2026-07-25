"""Command-line interface for openstack-janitor."""

from __future__ import annotations

from enum import Enum
from typing import Optional

import typer
from openstack.exceptions import SDKException
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from openstack_janitor.connection import get_connection
from openstack_janitor.detectors import get_detectors
from openstack_janitor.detectors.base import Detector, Finding
from openstack_janitor.reporting import (
    CleanAction,
    print_clean_plan,
    print_findings,
    render_html,
    render_json,
)

app = typer.Typer(
    help="Audit an OpenStack cloud for orphaned and wasteful resources.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = Console()
error_console = Console(stderr=True)


class OutputFormat(str, Enum):
    """Supported `--format` values for `janitor audit`."""

    table = "table"
    json = "json"
    html = "html"


def _select_detectors(detector: Optional[list[str]]) -> list[Detector]:
    """Resolve `--detector` names to Detector instances.

    Returns every registered detector when `detector` is None/empty. Exits
    with code 2 (after printing the unknown-name error to `error_console`)
    if any requested name is not registered.
    """
    all_detectors = get_detectors()
    if not detector:
        return all_detectors

    by_name = {d.name: d for d in all_detectors}
    unknown = [name for name in detector if name not in by_name]
    if unknown:
        valid = ", ".join(sorted(by_name)) or "(none registered)"
        error_console.print(
            f"[red]Unknown detector(s): {', '.join(unknown)}. Valid detectors: {valid}[/red]"
        )
        raise typer.Exit(code=2)
    return [by_name[name] for name in detector]


def _supports_clean(det: Detector) -> bool:
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


@app.callback()
def callback() -> None:
    """Audit an OpenStack cloud for orphaned and wasteful resources.

    A no-op callback: its only purpose is to keep Typer in "subcommand" mode
    (`janitor audit ...`, `janitor detectors`) instead of collapsing to a
    single implicit command.
    """


@app.command()
def detectors() -> None:
    """List registered detectors and their descriptions."""
    table = Table(title="Registered detectors")
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    for det in get_detectors():
        table.add_row(det.name, det.description)
    console.print(table)


@app.command()
def audit(
    cloud: Optional[str] = typer.Option(
        None,
        "--cloud",
        "-c",
        help="Named cloud from clouds.yaml (default: resolved from OS_CLOUD / OS_* env vars).",
    ),
    detector: Optional[list[str]] = typer.Option(
        None,
        "--detector",
        "-d",
        help="Run only this detector (repeatable). Default: run all registered detectors.",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.table,
        "--format",
        "-f",
        help="Output format: table for humans, json/html for reports or piping.",
    ),
) -> None:
    """Scan the cloud and report orphaned/wasteful resources.

    Exit codes: 0 = no findings, 1 = findings were reported (useful for cron
    jobs), 2 = an unknown --detector name was given, 3 = connecting to the
    cloud or scanning it failed. Exit-code behavior is the same for every
    --format.
    """
    selected = _select_detectors(detector)

    try:
        conn = get_connection(cloud)
    except SDKException as exc:
        error_console.print(f"[red]Failed to connect to OpenStack cloud: {escape(str(exc))}[/red]")
        raise typer.Exit(code=3) from exc

    try:
        findings = []
        for det in selected:
            findings.extend(det.detect(conn))
    except SDKException as exc:
        error_console.print(
            f"[red]Failed to scan the cloud for resources: {escape(str(exc))}[/red]"
        )
        raise typer.Exit(code=3) from exc

    if output_format is OutputFormat.json:
        # Machine-readable: use plain print(), never the rich console -- rich
        # would wrap lines and inject markup, corrupting the JSON output.
        print(render_json(findings))
    elif output_format is OutputFormat.html:
        print(render_html(findings))
    else:
        print_findings(findings, console)

    raise typer.Exit(code=1 if findings else 0)


@app.command()
def clean(
    cloud: Optional[str] = typer.Option(
        None,
        "--cloud",
        "-c",
        help="Named cloud from clouds.yaml (default: resolved from OS_CLOUD / OS_* env vars).",
    ),
    detector: Optional[list[str]] = typer.Option(
        None,
        "--detector",
        "-d",
        help=(
            "Detector to clean after (repeatable). Required: clean never acts on "
            "every detector at once."
        ),
    ),
    exclude: Optional[list[str]] = typer.Option(
        None,
        "--exclude",
        "-e",
        help=(
            "Resource ID to keep, even if flagged (repeatable) -- a manual keep-list. "
            "An ID that matches nothing is an error, so typos cannot silently delete."
        ),
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help=(
            "Actually delete flagged resources. Without this flag (the default), "
            "clean only previews what would be deleted -- nothing is touched."
        ),
    ),
) -> None:
    """Delete resources flagged by the given detectors.

    WARNING: this is destructive. With --yes, it deletes real cloud
    resources, and deletes are irreversible. Dry run (the default, no
    --yes) never deletes anything -- it only previews what would be
    deleted.

    --detector is required: clean deliberately refuses to act on every
    detector at once, so one command can never delete across all resource
    types. Note that some detectors have no age threshold (orphaned-ports,
    unused-security-groups), so they can flag resources created seconds
    ago -- prefer --exclude and narrow --detector until tag/age safety
    rails (janitor:keep) land.

    Findings are re-detected fresh right before acting -- clean never acts
    on stale findings from an earlier `audit` run. That also means a dry
    run does not bind the following execute: a resource created in between
    is deleted without having appeared in the reviewed preview.

    Deletes are asynchronous in OpenStack: a successful call means the
    delete was accepted, not that the resource is already gone.

    Exit codes: dry run always exits 0. With --yes: 0 if every deletion was
    accepted, 1 if any resource was not deleted -- either the deletion failed
    or the detector does not support cleaning (failures are isolated
    per-resource and do not stop the others). 2 = an unknown --detector name,
    no --detector at all, or an --exclude ID that matched nothing. 3 =
    connecting to the cloud or scanning it failed.
    """
    if not detector:
        valid = ", ".join(sorted(d.name for d in get_detectors())) or "(none registered)"
        error_console.print(
            "[red]clean requires at least one --detector so it never deletes across "
            f"every resource type at once. Valid detectors: {valid}[/red]"
        )
        raise typer.Exit(code=2)

    selected = _select_detectors(detector)
    exclude_ids = set(exclude or [])

    try:
        conn = get_connection(cloud)
    except SDKException as exc:
        error_console.print(f"[red]Failed to connect to OpenStack cloud: {exc}[/red]")
        raise typer.Exit(code=3) from exc

    try:
        # Detect everything up front: a detection failure must delete nothing.
        findings_by_detector: list[tuple[Detector, list[Finding]]] = [
            (det, det.detect(conn)) for det in selected
        ]
    except SDKException as exc:
        error_console.print(f"[red]Failed to scan the cloud for resources: {exc}[/red]")
        raise typer.Exit(code=3) from exc

    # A keep-list entry that matches nothing is almost always a typo (or a
    # name pasted where an ID belongs). Refusing to continue is what keeps a
    # mistyped --exclude from silently deleting the resource it meant to save.
    detected_ids = {f.resource_id for _, findings in findings_by_detector for f in findings}
    unmatched = sorted(exclude_ids - detected_ids)
    if unmatched:
        error_console.print(
            f"[red]--exclude matched no flagged resource: {', '.join(unmatched)}. "
            "Excludes must be resource IDs (not names) that appear in the findings; "
            "nothing was deleted.[/red]"
        )
        raise typer.Exit(code=2)

    actions: list[CleanAction] = []
    any_failed = False
    detected = sum(len(findings) for _, findings in findings_by_detector)

    def _action(finding: Finding, status: str) -> CleanAction:
        return CleanAction(
            resource_type=finding.resource_type,
            resource_id=finding.resource_id,
            resource_name=finding.resource_name,
            status=status,
        )

    try:
        for det, findings in findings_by_detector:
            for finding in findings:
                if finding.resource_id in exclude_ids:
                    status = "skipped"
                elif not yes:
                    # Preview must not promise a delete a detector cannot do.
                    status = "would-delete" if _supports_clean(det) else "unsupported"
                else:
                    try:
                        det.clean(conn, finding)
                    except NotImplementedError:
                        # Audit-only detector: report, never treat as deleted.
                        any_failed = True
                        error_console.print(
                            f"[red]{escape(det.name)} does not support clean; "
                            f"{escape(finding.resource_id)} left alone.[/red]"
                        )
                        status = "unsupported"
                    except Exception as exc:  # noqa: BLE001 - isolate per resource
                        any_failed = True
                        # Name the exception type so a bug in janitor is not
                        # mistaken for the cloud rejecting the delete, and
                        # escape it -- messages carry cloud-supplied text.
                        error_console.print(
                            f"[red]Failed to delete {finding.resource_type} "
                            f"{escape(finding.resource_id)}: "
                            f"{type(exc).__name__}: {escape(str(exc))}[/red]"
                        )
                        status = "failed"
                    except BaseException:
                        # Ctrl-C and friends: this resource's fate is genuinely
                        # unknown (the call may have reached the server), so
                        # record it before unwinding rather than dropping it.
                        actions.append(_action(finding, "interrupted"))
                        raise
                    else:
                        status = "requested"
                actions.append(_action(finding, status))
    finally:
        # Always report, even on Ctrl-C or an unexpected error mid-run: the
        # user must never be left without a record of what was deleted.
        print_clean_plan(actions, console, executed=yes, detected=detected)

    if not yes:
        raise typer.Exit(code=0)
    raise typer.Exit(code=1 if any_failed else 0)


def main() -> None:
    """Console-script entry point (typer's ``app`` is not itself callable-as-main)."""
    app()


if __name__ == "__main__":
    main()
