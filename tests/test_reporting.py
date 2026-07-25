"""Tests for JSON and HTML rendering of findings."""

from __future__ import annotations

import json

from rich.console import Console

from openstack_janitor.detectors.base import Finding
from openstack_janitor.reporting import print_clean_plan, render_html, render_json


def _finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "resource_type": "security-group",
        "resource_id": "sg-0001",
        "resource_name": "test-sg",
        "project_id": "project-0001",
        "reason": "security group is not attached to any port or referenced by any rule",
        "extra": {"rules_count": "2"},
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def test_render_json_round_trips_with_extra() -> None:
    finding = _finding()

    data = json.loads(render_json([finding]))

    assert len(data) == 1
    assert data[0]["resource_type"] == "security-group"
    assert data[0]["resource_id"] == "sg-0001"
    assert data[0]["resource_name"] == "test-sg"
    assert data[0]["project_id"] == "project-0001"
    assert data[0]["reason"] == finding.reason
    assert data[0]["extra"] == {"rules_count": "2"}


def test_render_json_empty_findings() -> None:
    assert render_json([]) == "[]"
    assert json.loads(render_json([])) == []


def test_render_html_escapes_dangerous_name() -> None:
    finding = _finding(resource_name="<script>alert(1)</script>")

    output = render_html([finding])

    assert "<script>alert(1)</script>" not in output
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in output


def test_render_html_empty_findings_shows_no_findings_text() -> None:
    output = render_html([])

    assert "No findings" in output
    assert "<table" not in output


def test_render_html_contains_all_five_field_values() -> None:
    finding = _finding()

    output = render_html([finding])

    assert finding.resource_type in output
    assert finding.resource_id in output
    assert finding.resource_name in output
    assert finding.project_id in output
    assert finding.reason in output
    assert "<table" in output


def test_print_clean_plan_no_actions_but_findings_detected_warns(capsys) -> None:
    """An empty action list must never claim a clean cloud if findings existed."""
    print_clean_plan([], Console(), executed=True, detected=3)

    out = capsys.readouterr().out
    assert "nothing to clean" not in out.lower()
    assert "3 finding(s) were detected" in out


def test_print_clean_plan_no_actions_and_nothing_detected_is_clean(capsys) -> None:
    print_clean_plan([], Console(), executed=True, detected=0)

    assert "nothing to clean" in capsys.readouterr().out.lower()
