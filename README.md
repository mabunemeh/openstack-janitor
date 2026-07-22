# openstack-janitor

[![CI](https://github.com/mabunemeh/openstack-janitor/actions/workflows/ci.yml/badge.svg)](https://github.com/mabunemeh/openstack-janitor/actions/workflows/ci.yml)

A CLI that audits an OpenStack cloud for orphaned and wasteful resources.

**Status: early development.** Seven detectors are working — see
[Detectors](#detectors); more detectors and a `clean` command are coming — see
[Roadmap](#roadmap).

## Install

Requires Python **3.9+**. On older interpreters, pip automatically selects a
compatible older version of openstacksdk.

From [PyPI](https://pypi.org/project/openstack-janitor/):

```sh
pipx install openstack-janitor   # recommended for CLI use
# or
pip install openstack-janitor
```

Standalone Linux binary — no Python needed at all. Built against glibc 2.28,
so it runs on RHEL 8-era hosts whose system Python is too old for the package:

```sh
curl -LO https://github.com/mabunemeh/openstack-janitor/releases/latest/download/janitor-linux-x86_64
chmod +x janitor-linux-x86_64
./janitor-linux-x86_64 audit --cloud my-cloud
```

From source:

```sh
git clone https://github.com/mabunemeh/openstack-janitor
cd openstack-janitor
pip install -e .
```

> **Old distro pip (e.g. Ubuntu 22.04's pip 22.0):** source installs can fail
> with `No module named 'packaging.licenses'` — the distro-patched pip leaks
> the system's old `packaging` into the build environment. Installing from
> PyPI is unaffected. For source installs, use a fresh venv with an upgraded
> pip: `python3 -m venv .venv && .venv/bin/pip install -U pip`.

## Usage

```sh
janitor detectors
janitor audit
janitor audit -c my-cloud
janitor audit -d unattached-volumes -d orphaned-ports
janitor audit -f json > findings.json
janitor audit -f html > report.html
```

Short options: `-c` / `--cloud`, `-d` / `--detector`, `-f` / `--format`, `-h` / `--help`.

`janitor detectors` lists every registered detector (name and description)
without connecting to a cloud. Use the names it prints with
`audit --detector`.

`--format table` (the default) prints a rich table; `json` and `html` write
machine-readable / shareable reports to stdout.

Example output when orphaned volumes are found:

```
$ janitor audit --cloud my-cloud
              openstack-janitor findings
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Type          ┃ ID        ┃ Name    ┃ Project ┃ Reason                       ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ volume        │ a1b2c3d4… │ old-db  │ proj-1  │ volume is unattached         │
│               │           │         │         │ (status=available)           │
└───────────────┴───────────┴─────────┴─────────┴──────────────────────────────┘
$ echo $?
1
```

`janitor audit` exits `0` when nothing is found, `1` when findings were
reported (so it's safe to wire into a cron job or CI check), `2` if an
unknown `--detector` name is given, and `3` if connecting to the cloud
fails.

## Detectors

| Name | Flags |
| --- | --- |
| `unattached-volumes` | Volumes in `available` status with no attachments. |
| `unassociated-floating-ips` | Floating IPs not associated with any port. |
| `orphaned-ports` | Ports with no device owner and no device id. Infrastructure ports (DHCP, routers, load balancer VIPs) always carry one of these, so they are never flagged; a pre-created port awaiting attachment will be. |
| `old-snapshots` | Volume snapshots older than a threshold (default 90 days). |
| `shutoff-instances` | Instances in `SHUTOFF` status whose last update is older than a threshold (default 30 days). There is no "shutoff since" field in the Compute API, so the age is a conservative lower bound — the detector may under-report but never over-reports. |
| `unused-security-groups` | Security groups not attached to any port and not referenced as a `remote_group_id` by any rule. The per-project `default` group is always skipped. |
| `orphan-snapshot-images` | Glance images whose `block_device_mapping` references a Cinder volume snapshot that no longer exists. Includes hidden images. |

All detectors are read-only. Resources without a parseable timestamp are never
flagged by the age-based detectors. Thresholds become configurable once
`janitor.toml` support lands (see [Roadmap](#roadmap)).

## Authentication

`openstack-janitor` uses [openstacksdk](https://docs.openstack.org/openstacksdk/latest/)
for authentication, so anything openstacksdk understands works here too:

- A named cloud from `clouds.yaml` via `--cloud my-cloud` (or the `OS_CLOUD`
  environment variable).
- The standard `OS_*` environment variables (`OS_AUTH_URL`, `OS_USERNAME`,
  `OS_PASSWORD`, `OS_PROJECT_NAME`, etc.) if no cloud is specified.

See the openstacksdk
[configuration documentation](https://docs.openstack.org/openstacksdk/latest/user/config/configuration.html)
for the full resolution order and file locations.

## Roadmap

- A `clean` command with a `--dry-run` default and explicit `--yes` to act.
- `janitor.toml` for per-cloud configuration (which detectors run, age
  thresholds, exclusions).
- Safety rails: tagging/exclusion lists so resources can be marked "do not
  touch" before `clean` ever deletes anything.
