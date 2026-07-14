"""Tests for the unused-security-groups detector."""

from __future__ import annotations

from types import SimpleNamespace

from openstack_janitor.detectors.security_groups import UnusedSecurityGroupsDetector


def test_finds_unused_security_group(fake_conn, fake_security_group) -> None:
    group = fake_security_group(security_group_rules=[{"id": "rule-1"}, {"id": "rule-2"}])
    fake_conn.network.security_groups.return_value = [group]
    fake_conn.network.ports.return_value = []

    findings = UnusedSecurityGroupsDetector().detect(fake_conn)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.resource_type == "security-group"
    assert finding.resource_id == group.id
    assert finding.resource_name == group.name
    assert finding.project_id == group.project_id
    assert "not attached to any port or referenced by any rule" in finding.reason
    assert finding.extra == {"rules_count": "2"}


def test_ignores_group_attached_to_port(fake_conn, fake_security_group, fake_port) -> None:
    group = fake_security_group(id="sg-attached")
    port = fake_port(security_group_ids=["sg-attached"])
    fake_conn.network.security_groups.return_value = [group]
    fake_conn.network.ports.return_value = [port]

    findings = UnusedSecurityGroupsDetector().detect(fake_conn)

    assert findings == []


def test_ignores_group_referenced_as_remote_group(fake_conn, fake_security_group) -> None:
    referenced = fake_security_group(id="sg-referenced", security_group_rules=[])
    referencing = fake_security_group(
        id="sg-referencing",
        name="referencing-sg",
        security_group_rules=[{"id": "rule-1", "remote_group_id": "sg-referenced"}],
    )
    fake_conn.network.security_groups.return_value = [referenced, referencing]
    fake_conn.network.ports.return_value = []

    findings = UnusedSecurityGroupsDetector().detect(fake_conn)

    # "sg-referenced" is protected by the remote_group_id reference;
    # "sg-referencing" itself has no ports and is not referenced, so it is flagged.
    flagged_ids = {f.resource_id for f in findings}
    assert "sg-referenced" not in flagged_ids
    assert "sg-referencing" in flagged_ids


def test_remote_group_reference_as_rule_object(fake_conn, fake_security_group) -> None:
    # openstacksdk may hand back rules as resource objects rather than dicts.
    referenced = fake_security_group(id="sg-referenced", security_group_rules=[])
    referencing = fake_security_group(
        id="sg-referencing",
        name="referencing-sg",
        security_group_rules=[SimpleNamespace(id="rule-1", remote_group_id="sg-referenced")],
    )
    fake_conn.network.security_groups.return_value = [referenced, referencing]
    fake_conn.network.ports.return_value = []

    findings = UnusedSecurityGroupsDetector().detect(fake_conn)

    flagged_ids = {f.resource_id for f in findings}
    assert "sg-referenced" not in flagged_ids
    assert "sg-referencing" in flagged_ids


def test_default_group_never_flagged(fake_conn, fake_security_group) -> None:
    group = fake_security_group(name="default")
    fake_conn.network.security_groups.return_value = [group]
    fake_conn.network.ports.return_value = []

    findings = UnusedSecurityGroupsDetector().detect(fake_conn)

    assert findings == []


def test_missing_rules_attr_no_extra(fake_conn, fake_security_group) -> None:
    group = fake_security_group()
    del group.security_group_rules
    fake_conn.network.security_groups.return_value = [group]
    fake_conn.network.ports.return_value = []

    findings = UnusedSecurityGroupsDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].extra == {}


def test_name_none_is_handled(fake_conn, fake_security_group) -> None:
    group = fake_security_group(name=None)
    fake_conn.network.security_groups.return_value = [group]
    fake_conn.network.ports.return_value = []

    findings = UnusedSecurityGroupsDetector().detect(fake_conn)

    assert len(findings) == 1
    assert findings[0].resource_name == ""
