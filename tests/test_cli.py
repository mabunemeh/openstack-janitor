"""Tests for the `janitor audit` command."""

from __future__ import annotations

import json
import re
from unittest.mock import MagicMock, PropertyMock, patch

from keystoneauth1.exceptions import ConnectFailure
from openstack.exceptions import SDKException
from rich.console import Console
from rich.errors import MarkupError
from typer.testing import CliRunner

from openstack_janitor.cli import _UNCLAMPED_WIDTH, _out_console, app
from openstack_janitor.detectors.base import Finding

runner = CliRunner()

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    """Drop ANSI color codes from CLI output.

    Typer renders help through rich, which emits color when it detects a
    capable stream (it does under CI, not in a plain captured terminal). With
    color on, an option name like ``--cloud`` is split by escape codes between
    its hyphens, so a raw ``"--cloud" in output`` check fails only in CI.
    Strip the codes first so help-text assertions are colour-independent.
    """
    return _ANSI_RE.sub("", text)


class FakeDetector:
    def __init__(self, name: str, findings: list[Finding] | None = None) -> None:
        self.name = name
        self.description = f"fake detector {name}"
        self._findings = findings or []

    def detect(self, conn) -> list[Finding]:
        return self._findings


def test_audit_no_findings_exits_zero() -> None:
    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()),
        patch(
            "openstack_janitor.cli.get_detectors",
            return_value=[FakeDetector("unattached-volumes")],
        ),
    ):
        result = runner.invoke(app, ["audit"])

    assert result.exit_code == 0
    assert "No findings" in result.stdout


def test_audit_with_findings_exits_one_and_shows_table() -> None:
    finding = Finding(
        resource_type="volume",
        resource_id="vol-123",
        resource_name="orphan",
        project_id="proj-1",
        reason="volume is unattached (status=available)",
    )
    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()),
        patch(
            "openstack_janitor.cli.get_detectors",
            return_value=[FakeDetector("unattached-volumes", [finding])],
        ),
    ):
        result = runner.invoke(app, ["audit"])

    assert result.exit_code == 1
    assert "vol-123" in result.stdout
    assert "orphan" in result.stdout
    # Single registered detector → Detector column is hidden.
    assert "Detector" not in _strip_ansi(result.stdout)


def test_audit_multiple_detectors_shows_detector_column() -> None:
    vol = Finding(
        resource_type="volume",
        resource_id="vol-123",
        resource_name="orphan",
        project_id="proj-1",
        reason="volume is unattached (status=available)",
    )
    port = Finding(
        resource_type="port",
        resource_id="port-456",
        resource_name="orphan-port",
        project_id="proj-1",
        reason="port is down and unattached",
    )
    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()),
        patch(
            "openstack_janitor.cli.get_detectors",
            return_value=[
                FakeDetector("unattached-volumes", [vol]),
                FakeDetector("orphaned-ports", [port]),
            ],
        ),
    ):
        result = runner.invoke(app, ["audit"])

    out = _strip_ansi(result.stdout)
    assert result.exit_code == 1
    assert "Detector" in out
    assert "unattached-volumes" in out
    assert "orphaned-ports" in out


def test_audit_single_detector_flag_hides_detector_column() -> None:
    finding = Finding(
        resource_type="volume",
        resource_id="vol-123",
        resource_name="orphan",
        project_id="proj-1",
        reason="volume is unattached (status=available)",
    )
    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()),
        patch(
            "openstack_janitor.cli.get_detectors",
            return_value=[
                FakeDetector("unattached-volumes", [finding]),
                FakeDetector("orphaned-ports"),
            ],
        ),
    ):
        result = runner.invoke(app, ["audit", "-d", "unattached-volumes"])

    out = _strip_ansi(result.stdout)
    assert result.exit_code == 1
    assert "vol-123" in out
    assert "Detector" not in out
    assert "unattached-volumes" not in out


def test_audit_two_detector_flags_shows_detector_column() -> None:
    vol = Finding(
        resource_type="volume",
        resource_id="vol-123",
        resource_name="orphan",
        project_id="proj-1",
        reason="volume is unattached (status=available)",
    )
    port = Finding(
        resource_type="port",
        resource_id="port-456",
        resource_name="orphan-port",
        project_id="proj-1",
        reason="port is down and unattached",
    )
    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()),
        patch(
            "openstack_janitor.cli.get_detectors",
            return_value=[
                FakeDetector("unattached-volumes", [vol]),
                FakeDetector("orphaned-ports", [port]),
            ],
        ),
    ):
        result = runner.invoke(
            app,
            ["audit", "-d", "unattached-volumes", "-d", "orphaned-ports"],
        )

    out = _strip_ansi(result.stdout)
    assert result.exit_code == 1
    assert "Detector" in out
    assert "unattached-volumes" in out
    assert "orphaned-ports" in out


def test_audit_unknown_detector_exits_two() -> None:
    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()),
        patch(
            "openstack_janitor.cli.get_detectors",
            return_value=[FakeDetector("unattached-volumes")],
        ),
    ):
        result = runner.invoke(app, ["audit", "--detector", "does-not-exist"])

    assert result.exit_code == 2


def test_audit_short_options() -> None:
    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()) as mock_conn,
        patch(
            "openstack_janitor.cli.get_detectors",
            return_value=[
                FakeDetector("unattached-volumes"),
                FakeDetector("orphaned-ports"),
            ],
        ),
    ):
        result = runner.invoke(
            app,
            ["audit", "-c", "my-cloud", "-d", "unattached-volumes", "-f", "json"],
        )

    assert result.exit_code == 0
    assert json.loads(result.stdout) == []
    mock_conn.assert_called_once_with("my-cloud")


def test_audit_help_short_option() -> None:
    result = runner.invoke(app, ["audit", "-h"])

    assert result.exit_code == 0
    help_text = _strip_ansi(result.stdout)
    assert "-c" in help_text
    assert "--cloud" in help_text
    assert "-d" in help_text
    assert "--detector" in help_text
    assert "-f" in help_text
    assert "--format" in help_text


def test_audit_sdk_exception_exits_three() -> None:
    with (
        patch("openstack_janitor.cli.get_connection", side_effect=SDKException("auth failed")),
        patch(
            "openstack_janitor.cli.get_detectors",
            return_value=[FakeDetector("unattached-volumes")],
        ),
    ):
        result = runner.invoke(app, ["audit"])

    assert result.exit_code == 3


def test_audit_connect_failure_exits_three() -> None:
    """keystoneauth1 errors are not SDKException, but must still exit 3.

    Unreachable cloud, DNS failure and bad credentials all surface as
    keystoneauth1.exceptions.ClientException subclasses, which openstacksdk
    does not wrap -- catching only SDKException let the single most common
    real-world failure escape as an unhandled traceback with exit code 1.
    """
    with (
        patch(
            "openstack_janitor.cli.get_connection",
            side_effect=ConnectFailure("Unable to establish connection"),
        ),
        patch(
            "openstack_janitor.cli.get_detectors",
            return_value=[FakeDetector("unattached-volumes")],
        ),
    ):
        result = runner.invoke(app, ["audit"])

    assert result.exit_code == 3
    assert "Failed to connect to OpenStack cloud" in _strip_ansi(result.output)


def test_audit_scan_connect_failure_exits_three() -> None:
    """A keystoneauth1 failure mid-scan (expired token) must also exit 3."""
    det = FakeDetector("unattached-volumes")
    det.detect = MagicMock(side_effect=ConnectFailure("connection reset"))  # type: ignore[method-assign]

    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()),
        patch("openstack_janitor.cli.get_detectors", return_value=[det]),
    ):
        result = runner.invoke(app, ["audit"])

    assert result.exit_code == 3
    assert "Failed to scan the cloud for resources" in _strip_ansi(result.output)


def test_audit_format_json_with_findings_parses_and_exits_one() -> None:
    finding = Finding(
        resource_type="volume",
        resource_id="vol-123",
        resource_name="orphan",
        project_id="proj-1",
        reason="volume is unattached (status=available)",
    )
    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()),
        patch(
            "openstack_janitor.cli.get_detectors",
            return_value=[FakeDetector("unattached-volumes", [finding])],
        ),
    ):
        result = runner.invoke(app, ["audit", "--format", "json"])

    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert len(data) == 1
    assert data[0]["resource_id"] == "vol-123"
    assert data[0]["resource_type"] == "volume"
    assert data[0]["detector"] == "unattached-volumes"


def test_audit_format_json_no_findings_exits_zero_with_empty_array() -> None:
    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()),
        patch(
            "openstack_janitor.cli.get_detectors",
            return_value=[FakeDetector("unattached-volumes")],
        ),
    ):
        result = runner.invoke(app, ["audit", "--format", "json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == []


def test_audit_format_html_with_findings_contains_table() -> None:
    finding = Finding(
        resource_type="volume",
        resource_id="vol-123",
        resource_name="orphan",
        project_id="proj-1",
        reason="volume is unattached (status=available)",
    )
    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()),
        patch(
            "openstack_janitor.cli.get_detectors",
            return_value=[FakeDetector("unattached-volumes", [finding])],
        ),
    ):
        result = runner.invoke(app, ["audit", "--format", "html"])

    assert result.exit_code == 1
    assert "<table" in result.stdout
    assert "<th>Detector</th>" in result.stdout
    assert "unattached-volumes" in result.stdout


def test_audit_unknown_format_exits_nonzero() -> None:
    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()),
        patch(
            "openstack_janitor.cli.get_detectors",
            return_value=[FakeDetector("unattached-volumes")],
        ),
    ):
        result = runner.invoke(app, ["audit", "--format", "xml"])

    assert result.exit_code == 2


def test_detectors_lists_name_and_description() -> None:
    with patch(
        "openstack_janitor.cli.get_detectors",
        return_value=[
            FakeDetector("unattached-volumes"),
            FakeDetector("orphaned-ports"),
        ],
    ):
        result = runner.invoke(app, ["detectors"])

    assert result.exit_code == 0
    assert "unattached-volumes" in result.stdout
    assert "orphaned-ports" in result.stdout
    assert "fake detector unattached-volumes" in result.stdout
    assert "fake detector orphaned-ports" in result.stdout


def test_detectors_shows_live_registry() -> None:
    result = runner.invoke(app, ["detectors"])

    assert result.exit_code == 0
    assert "unattached-volumes" in result.stdout


def test_out_console_is_unclamped_when_output_is_piped(monkeypatch) -> None:
    """Piped output must not be clamped to rich's 80-column fallback."""
    monkeypatch.delenv("COLUMNS", raising=False)

    assert _out_console().width == _UNCLAMPED_WIDTH


def test_out_console_respects_explicit_columns(monkeypatch) -> None:
    """An explicit COLUMNS is a deliberate override and must win."""
    monkeypatch.setenv("COLUMNS", "120")

    assert _out_console().width != _UNCLAMPED_WIDTH


def test_out_console_adapts_to_a_real_terminal(monkeypatch) -> None:
    """On a TTY the table should still fit the terminal, as before."""
    monkeypatch.delenv("COLUMNS", raising=False)

    with patch.object(Console, "is_terminal", new_callable=PropertyMock, return_value=True):
        console = _out_console()

    assert console.width != _UNCLAMPED_WIDTH


def test_audit_piped_output_keeps_full_resource_id() -> None:
    """Regression: a truncated id cannot be pasted into `clean --exclude`."""
    long_id = "a1b2c3d4-5678-90ab-cdef-1234567890ab"
    finding = Finding(
        resource_type="volume",
        resource_id=long_id,
        resource_name="very-long-volume-name-that-keeps-going-and-going",
        project_id="project-abcdef0123456789",
        reason="volume is unattached (status=available) and has been for a long time",
    )
    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()),
        patch(
            "openstack_janitor.cli.get_detectors",
            return_value=[FakeDetector("unattached-volumes", [finding])],
        ),
    ):
        result = runner.invoke(app, ["audit"])

    out = _strip_ansi(result.stdout)
    assert long_id in out
    assert "very-long-volume-name-that-keeps-going-and-going" in out
    assert "\u2026" not in out


def _finding_with_extra() -> Finding:
    return Finding(
        resource_type="volume",
        resource_id="vol-123",
        resource_name="orphan",
        project_id="proj-1",
        reason="volume is unattached (status=available)",
        extra={"size_gb": "100"},
    )


def _audit(args: list[str], finding: Finding):
    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()),
        patch(
            "openstack_janitor.cli.get_detectors",
            return_value=[FakeDetector("unattached-volumes", [finding])],
        ),
    ):
        return runner.invoke(app, args)


def test_audit_hides_extra_column_by_default() -> None:
    out = _strip_ansi(_audit(["audit"], _finding_with_extra()).stdout)

    assert "Extra" not in out
    assert "size_gb" not in out


def test_audit_long_shows_extra_column() -> None:
    out = _strip_ansi(_audit(["audit", "--long"], _finding_with_extra()).stdout)

    assert "Extra" in out
    assert "size_gb=100" in out


def test_audit_long_short_flag() -> None:
    out = _strip_ansi(_audit(["audit", "-l"], _finding_with_extra()).stdout)

    assert "size_gb=100" in out


def test_audit_long_with_empty_extra_renders() -> None:
    finding = Finding(
        resource_type="volume",
        resource_id="vol-123",
        resource_name="orphan",
        project_id="proj-1",
        reason="volume is unattached (status=available)",
    )

    result = _audit(["audit", "--long"], finding)

    assert result.exit_code == 1
    assert "vol-123" in _strip_ansi(result.stdout)


def test_audit_long_escapes_markup_in_extra() -> None:
    """extra values are cloud-supplied and must not be parsed as rich markup."""
    finding = Finding(
        resource_type="volume",
        resource_id="vol-123",
        resource_name="orphan",
        project_id="proj-1",
        reason="volume is unattached (status=available)",
        extra={"note": "[/red]evil[bold"},
    )

    result = _audit(["audit", "--long"], finding)

    assert result.exit_code == 1
    # Rendering the table at all proves the markup was escaped, not parsed.
    assert not isinstance(result.exception, MarkupError)
    assert "evil" in _strip_ansi(result.stdout)
