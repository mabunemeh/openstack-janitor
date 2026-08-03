"""Tests for the `janitor clean` command."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

from keystoneauth1.exceptions import ConnectFailure
from openstack.exceptions import SDKException
from typer.testing import CliRunner

from openstack_janitor.cli import app
from openstack_janitor.config import Config, ConfigError
from openstack_janitor.detectors.base import Detector, Finding

runner = CliRunner()


class FakeDetector:
    def __init__(
        self,
        name: str,
        findings: list[Finding] | None = None,
        *,
        fail_ids: set[str] | None = None,
        raise_on_clean: BaseException | None = None,
        raise_at_id: str | None = None,
    ) -> None:
        self.name = name
        self.description = f"fake detector {name}"
        self._findings = findings or []
        self._fail_ids = fail_ids or set()
        self._raise_on_clean = raise_on_clean
        self._raise_at_id = raise_at_id
        self.cleaned: list[str] = []
        self.detect_calls = 0

    def detect(self, conn: Any) -> list[Finding]:
        self.detect_calls += 1
        return self._findings

    def clean(self, conn: Any, finding: Finding) -> None:
        if self._raise_on_clean is not None and self._raise_at_id in (None, finding.resource_id):
            raise self._raise_on_clean
        if finding.resource_id in self._fail_ids:
            raise SDKException(f"could not delete {finding.resource_id}")
        self.cleaned.append(finding.resource_id)


class AuditOnlyDetector(FakeDetector):
    """A detector that deliberately does not implement deletion."""

    def clean(self, conn: Any, finding: Finding) -> None:
        raise NotImplementedError("AuditOnlyDetector does not support clean")


class NoCleanDetector(Detector):
    """A Detector subclass that inherits the base clean stub (no override)."""

    name = "no-clean"
    description = "audit-only stub with no clean override"

    def __init__(self, findings: list[Finding] | None = None) -> None:
        self._findings = findings or []
        self.cleaned: list[str] = []
        self.detect_calls = 0

    def detect(self, conn: Any) -> list[Finding]:
        self.detect_calls += 1
        return self._findings


def _finding(resource_id: str = "vol-123", **overrides: Any) -> Finding:
    defaults = {
        "resource_type": "volume",
        "resource_id": resource_id,
        "resource_name": "orphan",
        "project_id": "proj-1",
        "reason": "volume is unattached (status=available)",
    }
    defaults.update(overrides)
    return Finding(**defaults)


def _run(
    args: list[str],
    detectors: list[Any],
    *,
    input: str | None = None,
    can_prompt: bool = True,
    **patches: Any,
):
    """Invoke the CLI with get_connection/get_detectors patched."""
    connection = patches.pop("connection", None) or MagicMock()
    with (
        patch("openstack_janitor.cli.get_connection", return_value=connection),
        patch("openstack_janitor.cli.get_detectors", return_value=list(detectors)),
        patch("openstack_janitor.cli._can_prompt", return_value=can_prompt),
    ):
        return runner.invoke(app, args, input=input)


def test_clean_dry_run_does_not_call_clean_and_previews() -> None:
    det = FakeDetector("unattached-volumes", [_finding()])

    result = _run(["clean", "-d", "unattached-volumes", "--dry-run"], [det])

    assert result.exit_code == 0
    assert det.cleaned == []
    assert det.detect_calls == 1
    assert "would" in result.stdout.lower()
    assert "Dry run" in result.stdout
    assert "--dry-run" in result.stdout


def test_clean_prompt_preview_is_not_labeled_dry_run() -> None:
    """Bare clean prints a plan, not a dry-run summary, before prompting."""
    det = FakeDetector("unattached-volumes", [_finding()])

    result = _run(["clean", "-d", "unattached-volumes"], [det], input="n\n")

    assert result.exit_code == 0
    assert "Dry run" not in result.stdout
    assert "1 resource(s) would be deleted" in result.stdout


def test_clean_dry_short_flag() -> None:
    det = FakeDetector("unattached-volumes", [_finding()])

    result = _run(["clean", "-d", "unattached-volumes", "--dry"], [det])

    assert result.exit_code == 0
    assert det.cleaned == []
    assert "would" in result.stdout.lower()


def test_clean_requires_explicit_detector() -> None:
    """Without --detector, clean must refuse rather than act on everything."""
    det = FakeDetector("unattached-volumes", [_finding()])

    result = _run(["clean", "--yes"], [det])

    assert result.exit_code == 2
    assert det.cleaned == []


def test_clean_dry_run_and_yes_conflict() -> None:
    det = FakeDetector("unattached-volumes", [_finding()])

    result = _run(["clean", "-d", "unattached-volumes", "--dry-run", "--yes"], [det])

    assert result.exit_code == 2
    assert det.cleaned == []
    assert det.detect_calls == 0


def test_clean_prompt_yes_deletes() -> None:
    det = FakeDetector("unattached-volumes", [_finding()])

    result = _run(["clean", "-d", "unattached-volumes"], [det], input="y\n")

    assert result.exit_code == 0
    assert det.cleaned == ["vol-123"]
    assert det.detect_calls == 1
    assert "1 deletion(s) requested" in result.stdout


def test_clean_prompt_yes_word_deletes() -> None:
    det = FakeDetector("unattached-volumes", [_finding()])

    result = _run(["clean", "-d", "unattached-volumes"], [det], input="yes\n")

    assert result.exit_code == 0
    assert det.cleaned == ["vol-123"]


def test_clean_prompt_no_aborts_without_deleting() -> None:
    det = FakeDetector("unattached-volumes", [_finding()])

    result = _run(["clean", "-d", "unattached-volumes"], [det], input="n\n")

    assert result.exit_code == 0
    assert det.cleaned == []
    assert det.detect_calls == 1
    assert "aborted" in result.stdout.lower()


def test_clean_non_interactive_without_yes_exits_two() -> None:
    det = FakeDetector("unattached-volumes", [_finding()])

    result = _run(["clean", "-d", "unattached-volumes"], [det], can_prompt=False)

    assert result.exit_code == 2
    assert det.cleaned == []
    assert "non-interactive" in result.stdout.lower() or "non-interactive" in result.stderr.lower()


def test_clean_execute_calls_clean_and_reports_requested() -> None:
    det = FakeDetector("unattached-volumes", [_finding()])

    result = _run(["clean", "-d", "unattached-volumes", "--yes"], [det])

    assert result.exit_code == 0
    assert det.cleaned == ["vol-123"]
    assert det.detect_calls == 1
    assert "1 deletion(s) requested" in result.stdout


def test_clean_detects_once_when_deleting() -> None:
    """Preview and execute must share a single detection pass."""
    det = FakeDetector("unattached-volumes", [_finding()])

    result = _run(["clean", "-d", "unattached-volumes", "--yes"], [det])

    assert result.exit_code == 0
    assert det.detect_calls == 1


def test_clean_exclude_skips_resource() -> None:
    keep = _finding(resource_id="vol-keep")
    delete = _finding(resource_id="vol-delete")
    det = FakeDetector("unattached-volumes", [keep, delete])

    result = _run(
        ["clean", "-d", "unattached-volumes", "--yes", "--exclude", "vol-keep"],
        [det],
    )

    assert result.exit_code == 0
    assert det.cleaned == ["vol-delete"]
    assert "1 skipped" in result.stdout


def test_clean_short_yes_actually_deletes() -> None:
    """-y must enable execution, not merely be accepted as a flag."""
    det = FakeDetector("unattached-volumes", [_finding(resource_id="vol-1")])

    result = _run(["clean", "-d", "unattached-volumes", "-y"], [det])

    assert result.exit_code == 0
    assert det.cleaned == ["vol-1"]


def test_clean_exclude_is_honored_in_dry_run() -> None:
    """The preview must apply the same exclude filtering as the execute."""
    keep = _finding(resource_id="vol-keep")
    other = _finding(resource_id="vol-other")
    det = FakeDetector("unattached-volumes", [keep, other])

    result = _run(
        ["clean", "-d", "unattached-volumes", "--dry-run", "--exclude", "vol-keep"],
        [det],
    )

    assert result.exit_code == 0
    assert det.cleaned == []
    assert "skipped" in result.stdout.lower()


def test_clean_unmatched_exclude_aborts_without_deleting() -> None:
    """A typo'd keep-list entry must stop the run, not be silently ignored."""
    det = FakeDetector("unattached-volumes", [_finding(resource_id="vol-real")])

    result = _run(
        ["clean", "-d", "unattached-volumes", "--yes", "--exclude", "typo-not-an-id"],
        [det],
    )

    assert result.exit_code == 2
    assert det.cleaned == []


def test_clean_failure_is_isolated_and_exits_one() -> None:
    ok = _finding(resource_id="vol-ok")
    bad = _finding(resource_id="vol-bad")
    det = FakeDetector("unattached-volumes", [ok, bad], fail_ids={"vol-bad"})

    result = _run(["clean", "-d", "unattached-volumes", "--yes"], [det])

    assert result.exit_code == 1
    assert det.cleaned == ["vol-ok"]
    assert "1 failed" in result.stdout


def test_clean_non_sdk_exception_is_reported_not_swallowed() -> None:
    """A non-SDKException must be isolated per resource and still reported."""
    det = FakeDetector(
        "unattached-volumes",
        [_finding(resource_id="vol-1")],
        raise_on_clean=RuntimeError("token expired"),
    )

    result = _run(["clean", "-d", "unattached-volumes", "--yes"], [det])

    assert result.exit_code == 1
    assert "1 failed" in result.stdout


def test_clean_reports_what_was_done_when_interrupted() -> None:
    """Ctrl-C mid-run must still print the record of what was already deleted."""
    det = FakeDetector(
        "unattached-volumes",
        [_finding(resource_id="vol-1"), _finding(resource_id="vol-2")],
        raise_on_clean=KeyboardInterrupt(),
        raise_at_id="vol-2",
    )

    result = _run(["clean", "-d", "unattached-volumes", "--yes"], [det])

    assert result.exit_code != 0
    assert det.cleaned == ["vol-1"]
    # The plan table is printed from a finally block, so the deletion that did
    # happen is still reported rather than lost with the interrupt.
    assert "vol-1" in result.stdout
    # The interrupted resource's fate is unknown -- it must not be omitted.
    assert "vol-2" in result.stdout
    assert "interrupted" in result.stdout


def test_clean_interrupt_on_first_resource_never_claims_nothing_to_clean() -> None:
    """An interrupt before the first record must not report a clean cloud."""
    det = FakeDetector(
        "unattached-volumes",
        [_finding(resource_id="vol-1")],
        raise_on_clean=KeyboardInterrupt(),
    )

    result = _run(["clean", "-d", "unattached-volumes", "--yes"], [det])

    assert result.exit_code != 0
    assert "nothing to clean" not in result.stdout.lower()
    assert "vol-1" in result.stdout


def test_clean_survives_markup_in_cloud_supplied_name() -> None:
    """A resource name containing rich markup must not break reporting."""
    det = FakeDetector(
        "unattached-volumes",
        [_finding(resource_id="vol-1", resource_name="[/red]evil[bold")],
    )

    result = _run(["clean", "-d", "unattached-volumes", "--yes"], [det])

    assert result.exit_code == 0
    assert det.cleaned == ["vol-1"]
    assert "1 deletion(s) requested" in result.stdout


def test_clean_survives_markup_in_error_message() -> None:
    """A cloud error message containing rich markup must not break reporting."""
    det = FakeDetector(
        "unattached-volumes",
        [_finding(resource_id="vol-1"), _finding(resource_id="vol-2")],
        raise_on_clean=SDKException("conflict [/red] see [req-abc]"),
        raise_at_id="vol-1",
    )

    result = _run(["clean", "-d", "unattached-volumes", "--yes"], [det])

    assert result.exit_code == 1
    # The failure must not abort the remaining resources.
    assert det.cleaned == ["vol-2"]
    assert "1 failed" in result.stdout


def test_clean_audit_only_detector_is_reported_unsupported() -> None:
    det = AuditOnlyDetector("audit-only", [_finding(resource_id="vol-1")])

    result = _run(["clean", "-d", "audit-only", "--yes"], [det])

    assert result.exit_code == 1
    assert "unsupported" in result.stdout.lower()


def test_clean_base_stub_detector_is_unsupported_alongside_deletes() -> None:
    """A detector that never overrides clean must stay unsupported mid-execute."""
    vol_det = FakeDetector("unattached-volumes", [_finding(resource_id="vol-1")])
    stub = NoCleanDetector([_finding(resource_id="stub-1")])

    result = _run(
        ["clean", "-d", "unattached-volumes", "-d", "no-clean", "--yes"],
        [vol_det, stub],
    )

    assert result.exit_code == 1
    assert vol_det.cleaned == ["vol-1"]
    assert stub.cleaned == []
    assert "unsupported" in result.stdout.lower()


def test_clean_routes_each_finding_to_its_own_detector() -> None:
    """Findings must be cleaned by the detector that produced them."""
    vol_det = FakeDetector("unattached-volumes", [_finding(resource_id="vol-1")])
    ip_det = FakeDetector(
        "unassociated-floating-ips",
        [_finding(resource_id="fip-1", resource_type="floating-ip")],
    )

    result = _run(
        ["clean", "-d", "unattached-volumes", "-d", "unassociated-floating-ips", "--yes"],
        [vol_det, ip_det],
    )

    assert result.exit_code == 0
    assert vol_det.cleaned == ["vol-1"]
    assert ip_det.cleaned == ["fip-1"]


def test_clean_short_options() -> None:
    det = FakeDetector("unattached-volumes", [_finding(resource_id="vol-keep")])
    connection = MagicMock()
    with (
        patch(
            "openstack_janitor.cli.get_connection", return_value=connection
        ) as mock_get_connection,
        patch("openstack_janitor.cli.get_detectors", return_value=[det]),
        patch("openstack_janitor.cli._can_prompt", return_value=True),
    ):
        result = runner.invoke(
            app,
            ["clean", "-c", "my-cloud", "-d", "unattached-volumes", "-e", "vol-keep", "-y"],
        )

    assert result.exit_code == 0
    assert det.cleaned == []
    mock_get_connection.assert_called_once_with("my-cloud")


def test_clean_unknown_detector_exits_two() -> None:
    det = FakeDetector("unattached-volumes")

    result = _run(["clean", "--detector", "does-not-exist", "--dry-run"], [det])

    assert result.exit_code == 2


def test_clean_connection_sdk_exception_exits_three() -> None:
    det = FakeDetector("unattached-volumes")
    with (
        patch("openstack_janitor.cli.get_connection", side_effect=SDKException("auth failed")),
        patch("openstack_janitor.cli.get_detectors", return_value=[det]),
    ):
        result = runner.invoke(app, ["clean", "-d", "unattached-volumes", "--yes"])

    assert result.exit_code == 3


def test_clean_detect_failure_deletes_nothing_and_exits_three() -> None:
    det = FakeDetector("unattached-volumes")
    det.detect = MagicMock(side_effect=SDKException("compute unreachable"))  # type: ignore[method-assign]

    result = _run(["clean", "-d", "unattached-volumes", "--yes"], [det])

    assert result.exit_code == 3
    assert det.cleaned == []


def test_clean_connect_failure_exits_three() -> None:
    """keystoneauth1 errors are not SDKException, but must still exit 3.

    Unreachable cloud, DNS failure and bad credentials all surface as
    keystoneauth1.exceptions.ClientException subclasses, which openstacksdk
    does not wrap -- catching only SDKException let them escape as an
    unhandled traceback with exit code 1.
    """
    det = FakeDetector("unattached-volumes", [_finding()])
    with (
        patch(
            "openstack_janitor.cli.get_connection",
            side_effect=ConnectFailure("Unable to establish connection"),
        ),
        patch("openstack_janitor.cli.get_detectors", return_value=[det]),
    ):
        result = runner.invoke(app, ["clean", "-d", "unattached-volumes", "--yes"])

    assert result.exit_code == 3
    assert det.cleaned == []


def test_clean_detect_connect_failure_deletes_nothing_and_exits_three() -> None:
    """A keystoneauth1 failure during detection must still delete nothing."""
    det = FakeDetector("unattached-volumes", [_finding()])
    det.detect = MagicMock(side_effect=ConnectFailure("connection reset"))  # type: ignore[method-assign]

    result = _run(["clean", "-d", "unattached-volumes", "--yes"], [det])

    assert result.exit_code == 3
    assert det.cleaned == []


def test_clean_no_findings_exits_zero_with_friendly_message() -> None:
    det = FakeDetector("unattached-volumes", [])

    result = _run(["clean", "-d", "unattached-volumes", "--dry-run"], [det])

    assert result.exit_code == 0
    assert "nothing to clean" in result.stdout.lower()


def _run_with_config(
    args: list[str],
    detectors: list[Any],
    config: Config,
    *,
    input: str | None = None,
    can_prompt: bool = True,
):
    """Like `_run`, but also patches `load_config` to return a fixed Config."""
    with (
        patch("openstack_janitor.cli.get_connection", return_value=MagicMock()),
        patch("openstack_janitor.cli.get_detectors", return_value=list(detectors)),
        patch("openstack_janitor.cli._can_prompt", return_value=can_prompt),
        patch("openstack_janitor.cli.load_config", return_value=config),
    ):
        return runner.invoke(app, args, input=input)


def test_clean_config_error_exits_two() -> None:
    det = FakeDetector("unattached-volumes", [_finding()])
    with (
        patch("openstack_janitor.cli.get_detectors", return_value=[det]),
        patch(
            "openstack_janitor.cli.load_config",
            side_effect=ConfigError("/bad/janitor.toml: invalid TOML: boom"),
        ),
    ):
        result = runner.invoke(
            app, ["clean", "-d", "unattached-volumes", "--config", "/bad/janitor.toml", "--yes"]
        )

    assert result.exit_code == 2
    assert "invalid TOML" in result.output
    assert det.cleaned == []


def test_clean_config_exclude_merges_with_cli_exclude() -> None:
    """A config keep-list is skipped just like a matching -e, with no flag needed."""
    keep = _finding(resource_id="vol-config-keep")
    delete = _finding(resource_id="vol-delete")
    det = FakeDetector("unattached-volumes", [keep, delete])
    config = Config(exclude=("vol-config-keep",), source="/fake/janitor.toml")

    result = _run_with_config(["clean", "-d", "unattached-volumes", "--yes"], [det], config)

    assert result.exit_code == 0
    assert det.cleaned == ["vol-delete"]
    assert "1 skipped" in result.stdout


def test_clean_config_exclude_unmatched_does_not_abort() -> None:
    """A standing keep-list routinely names resources that aren't flagged right now."""
    det = FakeDetector("unattached-volumes", [_finding(resource_id="vol-1")])
    config = Config(exclude=("some-other-resource-not-flagged",), source="/fake/janitor.toml")

    result = _run_with_config(["clean", "-d", "unattached-volumes", "--yes"], [det], config)

    assert result.exit_code == 0
    assert det.cleaned == ["vol-1"]


def test_clean_cli_exclude_unmatched_still_aborts_with_config_present() -> None:
    """A -e typo must still abort even when a (non-matching) config exclude exists."""
    det = FakeDetector("unattached-volumes", [_finding(resource_id="vol-real")])
    config = Config(exclude=("vol-real",), source="/fake/janitor.toml")

    result = _run_with_config(
        ["clean", "-d", "unattached-volumes", "--yes", "--exclude", "typo-not-an-id"],
        [det],
        config,
    )

    assert result.exit_code == 2
    assert det.cleaned == []


def test_clean_config_exclude_unhashable_item_is_config_error_not_crash(tmp_path) -> None:
    """A nested-list exclude item must fail at config validation with a clean
    ConfigError, not crash `clean` with an unhashable-type TypeError at the
    set() union -- and it must do so before any detector is even run."""
    config_path = tmp_path / "janitor.toml"
    config_path.write_text("[clean]\nexclude = [[1]]\n", encoding="utf-8")
    det = FakeDetector("unattached-volumes", [_finding()])

    with patch("openstack_janitor.cli.get_detectors", return_value=[det]):
        result = runner.invoke(
            app,
            ["clean", "-d", "unattached-volumes", "--config", str(config_path), "--yes"],
        )

    assert result.exit_code == 2
    assert "exclude" in result.output.lower()
    assert det.detect_calls == 0
    assert det.cleaned == []


# --- safety rails: keep marker / min-age floor ------------------------------


def _recent_timestamp() -> str:
    """A created_at close enough to "now" to be younger than any positive floor."""
    return datetime.now(timezone.utc).isoformat()


def _advancing_clock(*instants: datetime) -> type[datetime]:
    """Build a `datetime` subclass whose `.now()` pops successive `instants`
    off a shared queue on each call, standing in for the real wall clock so
    a test can make "time pass" between two `.now()` calls deterministically
    -- without a real `time.sleep`. `fromisoformat` and everything else is
    inherited unchanged from the real `datetime`.
    """
    queue = list(instants)

    class _FakeDateTime(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:
            # The last instant is sticky: an extra .now() call must not blow up
            # with IndexError, or a regression fails for the wrong reason and
            # hides the assertion message that explains what actually broke.
            return queue.pop(0) if len(queue) > 1 else queue[0]

    return _FakeDateTime


def test_clean_keep_marker_finding_is_never_cleaned() -> None:
    det = FakeDetector("unattached-volumes", [_finding(markers=("janitor:keep",))])

    result = _run(["clean", "-d", "unattached-volumes", "--yes"], [det])

    assert result.exit_code == 0
    assert det.cleaned == []
    assert "protected" in result.stdout.lower()


def test_clean_too_new_finding_is_never_cleaned() -> None:
    det = FakeDetector("unattached-volumes", [_finding(created_at=_recent_timestamp())])
    config = Config(min_age_days=30.0)

    result = _run_with_config(["clean", "-d", "unattached-volumes", "--yes"], [det], config)

    assert result.exit_code == 0
    assert det.cleaned == []
    assert "too-new" in result.stdout


def test_clean_missing_created_at_with_active_floor_is_too_new() -> None:
    """Fail closed: a resource with no usable timestamp is never deleted once
    a min-age floor is active, rather than assuming it is old enough."""
    det = FakeDetector("unattached-volumes", [_finding()])  # created_at defaults to ""
    config = Config(min_age_days=10.0)

    result = _run_with_config(["clean", "-d", "unattached-volumes", "--yes"], [det], config)

    assert result.exit_code == 0
    assert det.cleaned == []
    assert "too-new" in result.stdout


def test_clean_mixed_age_run_deletes_only_the_eligible_resource() -> None:
    old = _finding(resource_id="vol-old", created_at="2000-01-01T00:00:00Z")
    new = _finding(resource_id="vol-new", created_at=_recent_timestamp())
    det = FakeDetector("unattached-volumes", [old, new])
    config = Config(min_age_days=30.0)

    result = _run_with_config(["clean", "-d", "unattached-volumes", "--yes"], [det], config)

    assert result.exit_code == 0
    assert det.cleaned == ["vol-old"]


def test_clean_all_protected_run_exits_zero_and_never_prompts() -> None:
    det = FakeDetector("unattached-volumes", [_finding(markers=("janitor:keep",))])

    # No --yes and no --dry-run: if this tried to prompt without input it
    # would abort/error rather than exit 0, so a clean 0 here proves the
    # would-delete==0 short-circuit fired before any prompt was attempted.
    result = _run(["clean", "-d", "unattached-volumes"], [det])

    assert result.exit_code == 0
    assert det.cleaned == []
    assert "proceed with deletion" not in result.stdout.lower()


def test_clean_exclude_wins_over_keep_marker() -> None:
    finding = _finding(resource_id="vol-1", markers=("janitor:keep",))
    det = FakeDetector("unattached-volumes", [finding])

    result = _run(
        ["clean", "-d", "unattached-volumes", "--yes", "--exclude", "vol-1"],
        [det],
    )

    assert result.exit_code == 0
    assert det.cleaned == []
    assert "1 skipped" in result.stdout


def test_clean_negative_min_age_days_flag_rejected() -> None:
    """--min-age-days must be held to the same >= 0 standard as
    [safety].min_age_days -- otherwise it becomes a way to silently
    disable a configured floor instead of a documented override."""
    det = FakeDetector("unattached-volumes", [_finding()])
    config = Config(min_age_days=365.0)

    result = _run_with_config(
        ["clean", "-d", "unattached-volumes", "--yes", "--min-age-days", "-1"],
        [det],
        config,
    )

    assert result.exit_code == 2
    assert det.cleaned == []
    assert "min-age-days" in result.output.lower() or "min_age_days" in result.output.lower()


def test_clean_nan_min_age_days_flag_rejected() -> None:
    """NaN passes every comparison, so a naive `< 0` guard would let it
    through and then silently disarm a configured floor at the `> 0` test."""
    det = FakeDetector("unattached-volumes", [_finding()])
    config = Config(min_age_days=365.0)

    result = _run_with_config(
        ["clean", "-d", "unattached-volumes", "--yes", "--min-age-days", "nan"],
        [det],
        config,
    )

    assert result.exit_code == 2
    assert det.cleaned == []


def test_clean_min_age_days_flag_overrides_config() -> None:
    """--min-age-days must win even when [safety].min_age_days is disabled."""
    det = FakeDetector("unattached-volumes", [_finding(created_at=_recent_timestamp())])
    config = Config(min_age_days=0.0)

    result = _run_with_config(
        ["clean", "-d", "unattached-volumes", "--yes", "--min-age-days", "30"],
        [det],
        config,
    )

    assert result.exit_code == 0
    assert det.cleaned == []
    assert "too-new" in result.stdout


def test_clean_min_age_uses_one_clock_for_preview_and_execute() -> None:
    """Regression: age must be computed against ONE `now`, captured before
    the preview loop, not re-derived (e.g. in the execute loop, after a
    confirmation prompt). Re-deriving it would let a resource shown
    "too-new" in the printed plan cross the floor while the user reads the
    plan or answers the prompt, and then get deleted anyway -- exactly the
    outcome the rail exists to prevent.

    Needs a second, always-eligible finding alongside the borderline one:
    with only the borderline finding, the "0 would-delete -> exit before
    prompting" short-circuit fires in preview and the execute loop -- where
    the drift bug lives -- never even runs. `vol-old` (created in 2000) is
    old enough under any plausible clock reading and exists purely to get
    the run past that short-circuit and into the confirm/execute path,
    mirroring how the reviewer actually reproduced this: "plan said '1
    resource(s) would be deleted. 1 too new.' and the execute table showed
    BOTH as requested."

    Simulates wall-clock time passing between the preview and execute
    phases with a fake clock (`_advancing_clock`) instead of a real
    `time.sleep`, so the test is deterministic: the queue yields
    `before_floor` while the preview is being built and `after_floor` (2
    minutes later) once execute re-evaluates, for whichever code path
    actually calls `.now()`.

    Patches `datetime` in both `cli` (where the fix captures `now` once)
    and `age` (where the pre-fix code silently re-derived it per finding,
    per loop pass) -- whichever module actually calls `.now()` draws from
    this same shared queue, so this test fails against the pre-fix code and
    passes against the fix without needing two different test bodies.
    """
    before_floor = datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
    after_floor = before_floor + timedelta(minutes=2)
    borderline_created_at = (before_floor - timedelta(hours=23, minutes=59)).isoformat()

    # Pre-fix code calls .now() once per finding, per loop pass (2 findings x
    # 2 passes = 4 calls); the fix calls it exactly once, total, so only the
    # first instant is ever consumed. Queueing 4 keeps both code paths safe
    # from IndexError so the fix/no-fix contrast comes from the *assertions*
    # below, not an incidental exhausted-queue crash.
    fake_clock = _advancing_clock(before_floor, before_floor, after_floor, after_floor)

    always_eligible = _finding(resource_id="vol-old", created_at="2000-01-01T00:00:00Z")
    borderline = _finding(resource_id="vol-borderline", created_at=borderline_created_at)
    det = FakeDetector("unattached-volumes", [always_eligible, borderline])
    config = Config(min_age_days=1.0)

    with (
        patch("openstack_janitor.cli.datetime", fake_clock),
        patch("openstack_janitor.age.datetime", fake_clock),
    ):
        result = _run_with_config(["clean", "-d", "unattached-volumes", "--yes"], [det], config)

    assert result.exit_code == 0
    assert det.cleaned == ["vol-old"], (
        "vol-borderline was reported too-new in the printed plan but was deleted anyway -- "
        "age was re-derived against a later clock reading in the execute loop"
    )
    assert "too-new" in result.stdout
