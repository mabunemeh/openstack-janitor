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

from openstack_janitor.cli import _UNCLAMPED_WIDTH, _out_console, _select_detectors, app
from openstack_janitor.config import Config, ConfigError
from openstack_janitor.detectors.base import Finding
from openstack_janitor.detectors.snapshots import OldSnapshotsDetector

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
    assert "-C" in help_text
    assert "--config" in help_text


def test_detectors_help_shows_config_option() -> None:
    result = runner.invoke(app, ["detectors", "--help"])

    help_text = _strip_ansi(result.stdout)
    assert result.exit_code == 0
    assert "-C" in help_text
    assert "--config" in help_text


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


def _config_aware_get_detectors(detectors: list[FakeDetector]):
    """A `get_detectors` stand-in that honors `config.disabled`, like the real one."""

    def _get(config=None):
        if config is None:
            return list(detectors)
        return [d for d in detectors if d.name not in config.disabled]

    return _get


def test_audit_config_error_exits_two() -> None:
    with patch(
        "openstack_janitor.cli.load_config",
        side_effect=ConfigError("/bad/janitor.toml: invalid TOML: boom"),
    ):
        result = runner.invoke(app, ["audit", "--config", "/bad/janitor.toml"])

    assert result.exit_code == 2
    assert "invalid TOML" in _strip_ansi(result.output)


def test_audit_disabled_detector_is_not_run() -> None:
    vol = Finding(
        resource_type="volume",
        resource_id="vol-123",
        resource_name="orphan",
        project_id="proj-1",
        reason="volume is unattached (status=available)",
    )
    srv = Finding(
        resource_type="instance",
        resource_id="srv-123",
        resource_name="old-box",
        project_id="proj-1",
        reason="instance has been shutoff",
    )
    detectors = [
        FakeDetector("unattached-volumes", [vol]),
        FakeDetector("shutoff-instances", [srv]),
    ]
    config = Config(disabled=("shutoff-instances",), source="/fake/janitor.toml")
    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()),
        patch("openstack_janitor.cli.load_config", return_value=config),
        patch(
            "openstack_janitor.cli.get_detectors",
            side_effect=_config_aware_get_detectors(detectors),
        ),
    ):
        result = runner.invoke(app, ["audit", "--config", "/fake/janitor.toml"])

    out = _strip_ansi(result.stdout)
    assert result.exit_code == 1
    assert "vol-123" in out
    assert "srv-123" not in out


def test_audit_explicit_detector_overrides_disabled_with_stderr_note() -> None:
    srv = Finding(
        resource_type="instance",
        resource_id="srv-123",
        resource_name="old-box",
        project_id="proj-1",
        reason="instance has been shutoff",
    )
    detectors = [
        FakeDetector("unattached-volumes"),
        FakeDetector("shutoff-instances", [srv]),
    ]
    config = Config(disabled=("shutoff-instances",), source="/fake/janitor.toml")
    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()),
        patch("openstack_janitor.cli.load_config", return_value=config),
        patch(
            "openstack_janitor.cli.get_detectors",
            side_effect=_config_aware_get_detectors(detectors),
        ),
    ):
        result = runner.invoke(
            app, ["audit", "--config", "/fake/janitor.toml", "-d", "shutoff-instances"]
        )

    out = _strip_ansi(result.output)
    assert result.exit_code == 1
    assert "srv-123" in out
    assert "disabled in config" in out


def test_audit_all_detectors_disabled_exits_two_not_false_all_clear() -> None:
    """Nothing scanned must never look like "no findings" -- that is a false
    all-clear for a cron job or CI check reading exit code 0."""
    detectors = [FakeDetector("unattached-volumes"), FakeDetector("shutoff-instances")]
    config = Config(
        disabled=("unattached-volumes", "shutoff-instances"), source="/fake/janitor.toml"
    )
    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()),
        patch("openstack_janitor.cli.load_config", return_value=config),
        patch(
            "openstack_janitor.cli.get_detectors",
            side_effect=_config_aware_get_detectors(detectors),
        ),
    ):
        result = runner.invoke(app, ["audit", "--config", "/fake/janitor.toml"])

    out = _strip_ansi(result.output)
    assert result.exit_code == 2
    assert "No detectors enabled" in out
    assert "/fake/janitor.toml" in out
    assert "No findings" not in out


def test_select_detectors_reoptions_forced_disabled_detector() -> None:
    """An explicit -d override must still get its config-file options applied,
    not just get exempted from the disabled filter."""
    config = Config(
        disabled=("old-snapshots",),
        detector_options={"old-snapshots": {"max_age_days": 30}},
        source="/fake/janitor.toml",
    )

    selected = _select_detectors(["old-snapshots"], config)

    assert len(selected) == 1
    assert isinstance(selected[0], OldSnapshotsDetector)
    assert selected[0].max_age_days == 30


def test_detectors_annotates_disabled_when_config_present() -> None:
    config = Config(disabled=("orphaned-ports",), source="/fake/janitor.toml")
    with (
        patch("openstack_janitor.cli.load_config", return_value=config),
        patch(
            "openstack_janitor.cli.get_detectors",
            return_value=[
                FakeDetector("unattached-volumes"),
                FakeDetector("orphaned-ports"),
            ],
        ),
    ):
        result = runner.invoke(app, ["detectors", "--config", "/fake/janitor.toml"])

    out = _strip_ansi(result.stdout)
    assert result.exit_code == 0
    assert "Disabled" in out
    assert "orphaned-ports" in out


def test_detectors_no_disabled_column_without_config() -> None:
    with patch(
        "openstack_janitor.cli.get_detectors",
        return_value=[FakeDetector("unattached-volumes")],
    ):
        result = runner.invoke(app, ["detectors"])

    assert result.exit_code == 0
    assert "Disabled" not in _strip_ansi(result.stdout)


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
