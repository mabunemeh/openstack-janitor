"""Rendering findings to the terminal, JSON, or HTML."""

from __future__ import annotations

import dataclasses
import html
import json

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from openstack_janitor.detectors.base import Finding


@dataclasses.dataclass(frozen=True)
class CleanAction:
    """The outcome of (or plan for) deleting one resource via `janitor clean`."""

    resource_type: str
    resource_id: str
    resource_name: str
    status: str
    """One of "would-delete" (dry run), "requested", "failed", "skipped",
    "unsupported" (the detector defines no deletion) or "interrupted" (the run
    was aborted mid-delete, so the outcome is genuinely unknown).

    "requested" rather than "deleted": OpenStack deletes are asynchronous, so
    an accepted call means the delete is under way, not that it has finished.
    """


def render_table(findings: list[Finding], *, show_detector: bool = False) -> Table:
    """Build a rich Table summarizing the given findings.

    When ``show_detector`` is true, a Detector column is placed first so the
    kebab-case name is easy to copy into ``janitor clean -d``.
    """
    table = Table(title="openstack-janitor findings")
    if show_detector:
        # no_wrap: names must stay intact so they can be copied into clean -d.
        table.add_column("Detector", style="magenta", no_wrap=True)
    table.add_column("Type", style="cyan")
    table.add_column("ID", style="dim")
    table.add_column("Name")
    table.add_column("Project")
    table.add_column("Reason")

    for finding in findings:
        # escape(): names/ids come from the cloud, and an unbalanced "[/red]"
        # in one would otherwise be parsed as rich markup and raise.
        cells = []
        if show_detector:
            cells.append(escape(finding.detector))
        cells.extend(
            [
                escape(finding.resource_type),
                escape(finding.resource_id),
                escape(finding.resource_name),
                escape(finding.project_id),
                escape(finding.reason),
            ]
        )
        table.add_row(*cells)
    return table


def print_findings(
    findings: list[Finding], console: Console, *, show_detector: bool = False
) -> None:
    """Print findings as a table, or a clean-cloud message if there are none."""
    if not findings:
        console.print("[green]No findings — cloud looks clean.[/green]")
        return
    console.print(render_table(findings, show_detector=show_detector))


def render_json(findings: list[Finding]) -> str:
    """Render findings as an indented JSON array, for reports/piping."""
    return json.dumps([dataclasses.asdict(f) for f in findings], indent=2, sort_keys=True)


def render_html(findings: list[Finding]) -> str:
    """Render findings as a fully self-contained HTML document.

    Every dynamic value is passed through ``html.escape`` -- findings come
    from cloud-controlled resource names, which must never be trusted enough
    to interpolate into HTML unescaped.
    """
    summary = f"{len(findings)} finding{'s' if len(findings) != 1 else ''}"

    if not findings:
        body = "<p>No findings — cloud looks clean.</p>"
    else:
        rows = []
        for finding in findings:
            extra = ", ".join(f"{k}={v}" for k, v in finding.extra.items())
            cells = [
                finding.detector,
                finding.resource_type,
                finding.resource_id,
                finding.resource_name,
                finding.project_id,
                finding.reason,
                extra,
            ]
            row = "".join(f"<td>{html.escape(cell)}</td>" for cell in cells)
            rows.append(f"<tr>{row}</tr>")
        body = (
            "<table>\n"
            "<tr><th>Detector</th><th>Type</th><th>ID</th><th>Name</th><th>Project</th>"
            "<th>Reason</th><th>Extra</th></tr>\n" + "\n".join(rows) + "\n</table>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>openstack-janitor report</title>
<style>
body {{ font-family: sans-serif; margin: 2rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; }}
th {{ background: #eee; }}
</style>
</head>
<body>
<h1>openstack-janitor report</h1>
<p>{html.escape(summary)}</p>
{body}
</body>
</html>
"""


def render_clean_table(actions: list[CleanAction]) -> Table:
    """Build a rich Table summarizing the given clean actions."""
    table = Table(title="openstack-janitor clean")
    table.add_column("Type", style="cyan")
    table.add_column("ID", style="dim")
    table.add_column("Name")
    table.add_column("Action")

    for action in actions:
        # escape(): see render_table -- ids and names are cloud-controlled.
        table.add_row(
            escape(action.resource_type),
            escape(action.resource_id),
            escape(action.resource_name),
            action.status,
        )
    return table


def print_clean_plan(
    actions: list[CleanAction],
    console: Console,
    *,
    executed: bool,
    detected: int = 0,
) -> None:
    """Print the clean actions table plus a summary line.

    ``executed=False`` means this was a dry run: nothing was deleted, and the
    summary tells the caller how to actually delete. ``executed=True`` means
    each action's ``status`` reflects what really happened.

    ``detected`` is how many findings the detectors returned. It exists so an
    empty ``actions`` list cannot be reported as "nothing to clean" when there
    were in fact findings -- that happens when the run is interrupted before
    the first resource is recorded, and claiming a clean cloud there would be
    a lie about a delete that may already have reached the server.
    """
    if not actions:
        if detected:
            console.print(
                f"[red]Stopped before recording any action, but {detected} finding(s) "
                "were detected. A delete may already have been sent — verify with "
                "`janitor audit`.[/red]"
            )
            return
        console.print("[green]No findings — nothing to clean.[/green]")
        return

    console.print(render_clean_table(actions))

    if not executed:
        would_delete = sum(1 for action in actions if action.status == "would-delete")
        skipped = sum(1 for action in actions if action.status == "skipped")
        unsupported = sum(1 for action in actions if action.status == "unsupported")
        summary = (
            f"Dry run — {would_delete} resource(s) would be deleted. Re-run with --yes to delete."
        )
        if skipped:
            summary += f" {skipped} skipped (excluded)."
        if unsupported:
            # --yes cannot delete these, so never let the advice above imply it.
            summary += f" {unsupported} unsupported (detector cannot delete them)."
        console.print(f"[yellow]{summary}[/yellow]")
        return

    requested = sum(1 for action in actions if action.status == "requested")
    failed = sum(1 for action in actions if action.status == "failed")
    skipped = sum(1 for action in actions if action.status == "skipped")
    unsupported = sum(1 for action in actions if action.status == "unsupported")
    interrupted = sum(1 for action in actions if action.status == "interrupted")
    # Anything that is not a clean success must colour the summary red, so it
    # can never read green while the command exits non-zero.
    color = "red" if (failed or unsupported or interrupted) else "green"
    summary = (
        f"{requested} deletion(s) requested, {failed} failed, {skipped} skipped, "
        f"{unsupported} unsupported"
    )
    if interrupted:
        summary += f", {interrupted} interrupted (outcome unknown)"
    console.print(f"[{color}]{summary}.[/{color}]")
    if requested:
        console.print(
            "[dim]Deletes are asynchronous: verify with `janitor audit` "
            "or your cloud's dashboard.[/dim]"
        )
