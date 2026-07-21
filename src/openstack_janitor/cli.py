"""Command-line interface for openstack-janitor."""

from __future__ import annotations

from enum import Enum
from typing import Optional

import typer
from openstack.exceptions import SDKException
from rich.console import Console
from rich.table import Table

from openstack_janitor.connection import get_connection
from openstack_janitor.detectors import get_detectors
from openstack_janitor.reporting import print_findings, render_html, render_json

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
    jobs), 2 = an unknown --detector name was given, 3 = connection or
    authentication to the cloud failed. Exit-code behavior is the same for
    every --format.
    """
    all_detectors = get_detectors()
    selected = all_detectors
    if detector:
        by_name = {d.name: d for d in all_detectors}
        unknown = [name for name in detector if name not in by_name]
        if unknown:
            valid = ", ".join(sorted(by_name)) or "(none registered)"
            error_console.print(
                f"[red]Unknown detector(s): {', '.join(unknown)}. Valid detectors: {valid}[/red]"
            )
            raise typer.Exit(code=2)
        selected = [by_name[name] for name in detector]

    try:
        conn = get_connection(cloud)
        findings = []
        for det in selected:
            findings.extend(det.detect(conn))
    except SDKException as exc:
        error_console.print(f"[red]Failed to connect to OpenStack cloud: {exc}[/red]")
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


def main() -> None:
    """Console-script entry point (typer's ``app`` is not itself callable-as-main)."""
    app()


if __name__ == "__main__":
    main()
