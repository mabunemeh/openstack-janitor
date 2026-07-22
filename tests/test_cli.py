"""Tests for the `janitor audit` command."""

from __future__ import annotations

import json
import re
from unittest.mock import MagicMock, patch

from openstack.exceptions import SDKException
from typer.testing import CliRunner

from openstack_janitor.cli import app
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
