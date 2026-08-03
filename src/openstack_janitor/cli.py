"""Command-line interface for openstack-janitor."""

from __future__ import annotations

import dataclasses
import os
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from keystoneauth1.exceptions import ClientException as KeystoneAuthException
from openstack.exceptions import SDKException
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from openstack_janitor.age import age_in_days
from openstack_janitor.config import Config, ConfigError, load_config
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

# Talking to a cloud can fail in two disjoint exception trees: openstacksdk
# raises SDKException, but authentication and transport live one layer down in
# keystoneauth1, whose ClientException (ConnectFailure, Unauthorized,
# DiscoveryFailure, ...) is *not* a subclass of SDKException. The most common
# real-world failures -- unreachable cloud, DNS failure, bad credentials --
# come from keystoneauth1, so both trees must be caught or they escape as an
# unhandled traceback instead of the documented exit code 3.
CLOUD_ERRORS = (SDKException, KeystoneAuthException)

app = typer.Typer(
    help="Audit an OpenStack cloud for orphaned and wasteful resources.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
error_console = Console(stderr=True)

# Rich clamps to 80 columns when stdout is not a terminal, which truncates
# resource ids mid-string -- and piping to `less` or a file is exactly when the
# whole id is wanted, to paste into `clean --exclude`. So treat "not a terminal"
# as "do not clamp" and let the content decide the width. Tables size to their
# content, so this is a ceiling, not a fixed width.
_UNCLAMPED_WIDTH = 10_000


def _out_console() -> Console:
    """Build the console for human-facing output, sized for its destination.

    Must be called at print time, not import time: the stream is only known
    once the command runs.
    """
    console = Console()
    # A real terminal already reports the width the user wants to fit; an
    # explicit COLUMNS is a deliberate override. Respect both.
    if console.is_terminal or os.environ.get("COLUMNS"):
        return console
    return Console(width=_UNCLAMPED_WIDTH)


class OutputFormat(str, Enum):
    """Supported `--format` values for `janitor audit`."""

    table = "table"
    json = "json"
    html = "html"


def _load_config_or_exit(config_path: Optional[str]) -> Config:
    """Load janitor.toml (explicit path or auto-discovered); exit 2 on ConfigError."""
    try:
        return load_config(Path(config_path) if config_path else None)
    except ConfigError as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(code=2) from exc


def _select_detectors(
    detector: Optional[list[str]], config: Optional[Config] = None
) -> list[Detector]:
    """Resolve `--detector` names to Detector instances, honoring config disables.

    Returns every non-disabled registered detector when `detector` is
    None/empty. An explicit `-d <name>` for a detector disabled in config
    still runs it -- the flag overrides the config toggle, since the user
    typed it -- but prints a one-line note to `error_console`. Exits with
    code 2 (after printing the unknown-name error to `error_console`) if any
    requested name is not registered at all; the valid-names list there
    includes every registered detector, disabled or not.
    """
    enabled = get_detectors(config)
    if not detector:
        return enabled

    # Disabled is a config toggle, not deregistration: unknown-name detection
    # and the valid-names list, plus instantiation for an explicit override,
    # must see (and correctly option) every registered detector.
    all_config = dataclasses.replace(config, disabled=()) if config else None
    by_name = {d.name: d for d in get_detectors(all_config)}
    unknown = [name for name in detector if name not in by_name]
    if unknown:
        valid = ", ".join(sorted(by_name)) or "(none registered)"
        error_console.print(
            f"[red]Unknown detector(s): {', '.join(unknown)}. Valid detectors: {valid}[/red]"
        )
        raise typer.Exit(code=2)

    enabled_names = {d.name for d in enabled}
    for name in detector:
        if name not in enabled_names:
            error_console.print(
                f"[yellow]Note: detector '{name}' is disabled in config; running it "
                "anyway because it was explicitly requested with --detector.[/yellow]"
            )

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


def _can_prompt() -> bool:
    """Whether stdin can accept an interactive confirmation prompt."""
    return sys.stdin.isatty()


def _plan_status(
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
        return "skipped"
    if keep_marker in finding.markers:
        return "protected"
    if min_age_days > 0:
        age = age_in_days(finding.created_at, now=now)
        # Fail closed: a resource we cannot date is never deleted once a
        # floor is active, rather than assuming it is old enough.
        if age is None or age < min_age_days:
            return "too-new"
    if not _supports_clean(det):
        return "unsupported"
    return "would-delete"


@app.callback()
def callback() -> None:
    """Audit an OpenStack cloud for orphaned and wasteful resources.

    A no-op callback: its only purpose is to keep Typer in "subcommand" mode
    (`janitor audit ...`, `janitor detectors`) instead of collapsing to a
    single implicit command.
    """


@app.command()
def detectors(
    config_path: Optional[str] = typer.Option(
        None,
        "--config",
        "-C",
        help="Path to janitor.toml (default: auto-discover).",
    ),
) -> None:
    """List registered detectors and their descriptions."""
    config = _load_config_or_exit(config_path)
    show_disabled = bool(config.disabled)

    table = Table(title="Registered detectors")
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    if show_disabled:
        table.add_column("Disabled")
    for det in get_detectors():
        row = [det.name, det.description]
        if show_disabled:
            row.append("yes" if det.name in config.disabled else "")
        table.add_row(*row)
    _out_console().print(table)


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
    config_path: Optional[str] = typer.Option(
        None,
        "--config",
        "-C",
        help="Path to janitor.toml (default: auto-discover).",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.table,
        "--format",
        "-f",
        help="Output format: table for humans, json/html for reports or piping.",
    ),
    long: bool = typer.Option(
        False,
        "--long",
        "-l",
        help="Print all extra columns.",
    ),
) -> None:
    """Scan the cloud and report orphaned/wasteful resources.

    Exit codes: 0 = no findings, 1 = findings were reported (useful for cron
    jobs), 2 = an unknown --detector name was given, --config named a file
    that is missing/invalid, or every detector ended up disabled in config,
    3 = connecting to the cloud or scanning it failed. Exit-code behavior is
    the same for every --format.
    """
    config = _load_config_or_exit(config_path)
    selected = _select_detectors(detector, config)

    if not selected:
        # Every registered detector was disabled in config and none was
        # explicitly forced back in with -d: reporting "no findings" here
        # would be a false all-clear (nothing was actually scanned), which
        # is exactly the wrong thing to print to a cron job or CI check.
        error_console.print(
            f"[red]No detectors enabled (all disabled in {escape(config.source)}); "
            "nothing was scanned.[/red]"
        )
        raise typer.Exit(code=2)

    try:
        conn = get_connection(cloud)
    except CLOUD_ERRORS as exc:
        error_console.print(f"[red]Failed to connect to OpenStack cloud: {escape(str(exc))}[/red]")
        raise typer.Exit(code=3) from exc

    try:
        findings = []
        for det in selected:
            for finding in det.detect(conn):
                findings.append(dataclasses.replace(finding, detector=det.name))
    except CLOUD_ERRORS as exc:
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
        # Detector column is redundant when the user already narrowed to one -d.
        print_findings(
            findings,
            _out_console(),
            show_detector=len(selected) != 1,
            show_extra=long,
        )

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
    config_path: Optional[str] = typer.Option(
        None,
        "--config",
        "-C",
        help="Path to janitor.toml (default: auto-discover).",
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
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        "--dry",
        help="Preview what would be deleted and exit without prompting or deleting.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help=(
            "Delete without asking for confirmation. Without this flag, clean prints "
            "the plan and prompts before deleting (unless --dry-run)."
        ),
    ),
    min_age_days: Optional[float] = typer.Option(
        None,
        "--min-age-days",
        help="Minimum resource age in days before deleting (overrides safety.min_age_days).",
    ),
) -> None:
    """Delete resources flagged by the given detectors.

    WARNING: this is destructive. Deletes are irreversible. Modes:

    * --dry-run / --dry: print the plan and exit; nothing is deleted.
    * default: print the plan, prompt for confirmation, delete that set on yes.
    * --yes / -y: print the plan and delete without prompting.

    Within one invocation the printed plan is what gets deleted -- detection
    runs once. A later clean run re-detects from scratch.

    --detector is required: clean deliberately refuses to act on every
    detector at once, so one command can never delete across all resource
    types. Note that some detectors have no age threshold of their own
    (orphaned-ports, unused-security-groups), so they can flag resources
    created seconds ago -- narrow --detector and lean on the safety rails
    below for those.

    Safety rails, applied before anything is deleted: a resource carrying
    the keep marker (a tag, a metadata key, or an image property key --
    default "janitor:keep", configurable via safety.keep_marker) is
    never deleted and is reported "protected" instead. There is
    deliberately no flag to bypass this -- the only way to unprotect a
    resource is to remove the marker from it in the cloud. --min-age-days
    (or safety.min_age_days; the flag overrides the config value)
    additionally refuses to delete anything younger than the floor,
    reporting it "too-new" -- a resource with no usable creation
    timestamp is treated as too new whenever a floor is active, since
    what cannot be dated cannot be proven old enough.

    Findings are detected fresh for this run -- clean never acts on stale
    findings from an earlier `audit` run.

    Deletes are asynchronous in OpenStack: a successful call means the
    delete was accepted, not that the resource is already gone.

    janitor.toml's clean.exclude is a standing keep-list, merged with any
    --exclude values. Unlike --exclude, a config exclude that matches no
    finding is not an error -- a keep-list routinely names resources that
    are not currently flagged.

    Exit codes: dry run and declined confirmation exit 0. After deleting: 0
    if every deletion was accepted, 1 if any resource was not deleted --
    either the deletion failed or the detector does not support cleaning
    (failures are isolated per-resource and do not stop the others).
    Resources skipped, protected by the keep marker, or too new are
    intentional outcomes, not failures, and never affect the exit code. 2 =
    an unknown --detector name, no --detector at all, a --config file that
    is missing/invalid, an --exclude ID that matched nothing, a negative
    --min-age-days, --dry-run combined with --yes, or a confirmation prompt
    required on a non-interactive terminal. 3 = connecting to the cloud or
    scanning it failed.
    """
    if dry_run and yes:
        error_console.print(
            "[red]--dry-run and --yes cannot be used together. "
            "Pass --dry-run to preview only, or --yes to delete without prompting.[/red]"
        )
        raise typer.Exit(code=2)

    config = _load_config_or_exit(config_path)

    if not detector:
        valid = ", ".join(sorted(d.name for d in get_detectors())) or "(none registered)"
        error_console.print(
            "[red]clean requires at least one --detector so it never deletes across "
            f"every resource type at once. Valid detectors: {valid}[/red]"
        )
        raise typer.Exit(code=2)

    selected = _select_detectors(detector, config)
    cli_exclude_ids = set(exclude or [])
    exclude_ids = cli_exclude_ids | set(config.exclude)
    keep_marker = config.keep_marker
    effective_min_age_days = config.min_age_days if min_age_days is None else min_age_days
    if not effective_min_age_days >= 0:
        # Negated rather than `< 0` so NaN is rejected too: NaN passes every
        # comparison, so it would slip through and then fail the `> 0` test
        # that arms the rail -- silently disabling a configured floor, which
        # is the exact failure this check exists to prevent.
        # safety.min_age_days already rejects negatives at config-load time;
        # --min-age-days must be held to the same standard, or the two layers
        # disagree about what is valid.
        error_console.print(
            f"[red]--min-age-days must be a number >= 0, got {effective_min_age_days!r}.[/red]"
        )
        raise typer.Exit(code=2)

    try:
        conn = get_connection(cloud)
    except CLOUD_ERRORS as exc:
        error_console.print(f"[red]Failed to connect to OpenStack cloud: {escape(str(exc))}[/red]")
        raise typer.Exit(code=3) from exc

    try:
        # Detect everything up front: a detection failure must delete nothing.
        # One pass binds the preview to any later delete in this invocation.
        findings_by_detector: list[tuple[Detector, list[Finding]]] = [
            (det, det.detect(conn)) for det in selected
        ]
    except CLOUD_ERRORS as exc:
        error_console.print(
            f"[red]Failed to scan the cloud for resources: {escape(str(exc))}[/red]"
        )
        raise typer.Exit(code=3) from exc

    # A keep-list entry that matches nothing is almost always a typo (or a
    # name pasted where an ID belongs). Refusing to continue is what keeps a
    # mistyped --exclude from silently deleting the resource it meant to save.
    # This check is deliberately CLI --exclude only: config.exclude is a
    # standing keep-list that routinely names resources not currently
    # flagged, so it must not abort the run.
    detected_ids = {f.resource_id for _, findings in findings_by_detector for f in findings}
    unmatched = sorted(cli_exclude_ids - detected_ids)
    if unmatched:
        error_console.print(
            f"[red]--exclude matched no flagged resource: {', '.join(unmatched)}. "
            "Excludes must be resource IDs (not names) that appear in the findings; "
            "nothing was deleted.[/red]"
        )
        raise typer.Exit(code=2)

    detected = sum(len(findings) for _, findings in findings_by_detector)

    def _action(finding: Finding, status: str) -> CleanAction:
        return CleanAction(
            resource_type=finding.resource_type,
            resource_id=finding.resource_id,
            resource_name=finding.resource_name,
            status=status,
        )

    # Captured ONCE, before the preview loop, and reused for the execute loop
    # below: recomputing age against a fresh wall clock in the execute loop
    # would let a resource shown "too-new" in the printed plan cross the
    # floor while the user reads the plan or answers the confirmation
    # prompt, and then get deleted -- exactly what this rail exists to stop.
    now = datetime.now(timezone.utc)

    # Preview from this detection pass -- the same findings are deleted later.
    preview: list[CleanAction] = []
    for det, findings in findings_by_detector:
        for finding in findings:
            status = _plan_status(
                finding,
                det,
                exclude_ids=exclude_ids,
                keep_marker=keep_marker,
                min_age_days=effective_min_age_days,
                now=now,
            )
            preview.append(_action(finding, status))

    console = _out_console()
    print_clean_plan(preview, console, executed=False, detected=detected, dry_run=dry_run)

    would_delete = sum(1 for action in preview if action.status == "would-delete")
    if would_delete == 0:
        raise typer.Exit(code=0)

    if dry_run:
        raise typer.Exit(code=0)

    if not yes:
        if not _can_prompt():
            error_console.print(
                "[red]Refusing to prompt on a non-interactive terminal. "
                "Pass --yes to delete or --dry-run to preview only.[/red]"
            )
            raise typer.Exit(code=2)
        if not typer.confirm("Proceed with deletion?"):
            console.print("Aborted â€” nothing was deleted.")
            raise typer.Exit(code=0)

    actions: list[CleanAction] = []
    any_failed = False

    try:
        for det, findings in findings_by_detector:
            for finding in findings:
                status = _plan_status(
                    finding,
                    det,
                    exclude_ids=exclude_ids,
                    keep_marker=keep_marker,
                    min_age_days=effective_min_age_days,
                    now=now,
                )
                if status == "unsupported":
                    # Preview already marked these unsupported; still report
                    # them on execute so the record matches what was shown.
                    any_failed = True
                    error_console.print(
                        f"[red]{escape(det.name)} does not support clean; "
                        f"{escape(finding.resource_id)} left alone.[/red]"
                    )
                elif status == "would-delete":
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
        print_clean_plan(actions, console, executed=True, detected=detected)

    raise typer.Exit(code=1 if any_failed else 0)


def main() -> None:
    """Console-script entry point (typer's ``app`` is not itself callable-as-main)."""
    app()


if __name__ == "__main__":
    main()
