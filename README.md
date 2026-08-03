# openstack-janitor

[![CI](https://github.com/mabunemeh/openstack-janitor/actions/workflows/ci.yml/badge.svg)](https://github.com/mabunemeh/openstack-janitor/actions/workflows/ci.yml)

A CLI that audits an OpenStack cloud for orphaned and wasteful resources.

**Status: early development.** Seven detectors, a `clean` command, and
keep-marker/min-age safety rails are working — see [Detectors](#detectors)
and [Cleaning](#cleaning); more detectors are on the
[roadmap](#roadmap).

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
janitor audit --long
```

Short options: `-c` / `--cloud`, `-d` / `--detector`, `-C` / `--config`, `-f` / `--format`, `-h` / `--help`.

`--config` / `-C` points at a `janitor.toml`; without it, auto-discovery checks
(in order) `$JANITOR_CONFIG`, `./janitor.toml`, then
`~/.config/janitor/janitor.toml` (`$XDG_CONFIG_HOME` honoured). See
[Configuration](#configuration).

`janitor detectors` lists every registered detector (name and description)
without connecting to a cloud. Use the names it prints with
`audit --detector`.

`--format table` (the default) prints a rich table; `json` and `html` write
machine-readable / shareable reports to stdout.

`--long` / `-l` prints all extra columns.

Example output when orphaned volumes are found:

```
$ janitor audit --cloud my-cloud
              openstack-janitor findings
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Detector            ┃ Type   ┃ ID        ┃ Name    ┃ Project ┃ Reason                       ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ unattached-volumes  │ volume │ a1b2c3d4… │ old-db  │ proj-1  │ volume is unattached         │
│                     │        │           │         │         │ (status=available)           │
└─────────────────────┴────────┴───────────┴─────────┴─────────┴──────────────────────────────┘
$ echo $?
1
```

The **Detector** column appears when more than one detector runs (the default,
or two or more `-d` flags). With a single `-d`, the column is omitted. Use the
name to run `janitor clean -d <detector>`.

`janitor audit` exits `0` when nothing is found, `1` when findings were
reported (so it's safe to wire into a cron job or CI check), `2` if an
unknown `--detector` name is given or `--config` names a missing/invalid
file, and `3` if connecting to the cloud fails.

## Configuration

```toml
# janitor.toml
[detectors]
disabled = ["shutoff-instances"]          # detector names to skip (default: none)

[detectors.old-snapshots]
max_age_days = 30                          # default 90

[detectors.shutoff-instances]
max_age_days = 7                           # default 30

[clean]
exclude = ["vol-0001", "sg-0002"]          # standing keep-list, merged with -e

[safety]
keep_marker = "janitor:keep"               # default; see Cleaning
min_age_days = 7                           # default 0 (disabled)
```

`--detector` overrides a config-disabled detector; `--exclude` is merged with
`clean.exclude` rather than replacing it; `--min-age-days` overrides
`[safety].min_age_days`.

## Cleaning

```sh
janitor clean -d unattached-volumes --dry-run         # preview only, deletes nothing
janitor clean -d unattached-volumes                   # preview, then prompt before deleting
janitor clean -d unattached-volumes --yes             # preview and delete without prompting
janitor clean -d unattached-volumes -e vol-0001 --yes # keep specific resource IDs
```

`janitor clean` detects once, prints the plan for that set, then either exits
(`--dry-run`), asks for confirmation (default), or deletes without asking
(`--yes`). Deletes are real and irreversible: once a volume, snapshot,
floating IP, port, security group, instance, or image is gone, it is gone.

`--detector` is **required**. `clean` refuses to act on every detector at once,
so a single command can never delete across all seven resource types.

Read this before deleting:

- **Some detectors have no age threshold of their own.** `orphaned-ports` and
  `unused-security-groups` flag by state alone, so a port or group created
  seconds ago — mid-provisioning, mid-CI-run — is a finding. Keep
  `--detector` narrow, or lean on `--min-age-days` / the keep marker below.
- **Within one invocation the printed plan is what gets deleted.** Detection
  runs once; confirmation or `--yes` acts on that same set. A later `clean`
  run re-detects from scratch.
- **Cleaning can create new findings.** Deleting a shutoff instance leaves its
  volumes unattached; deleting snapshots orphans the images built from them.
  The next run will flag those. Re-read each plan rather than looping
  `--yes` blindly.
- **`--exclude` takes resource IDs, not names.** An `--exclude` value that
  matches no finding aborts the run rather than being ignored, so a typo
  cannot silently delete what it was meant to protect.
- **Deletes are asynchronous.** A successful call means the delete was
  accepted; verify with `janitor audit` afterwards.
- **Non-interactive terminals need `--yes` or `--dry-run`.** Bare `clean`
  refuses to prompt when stdin is not a TTY (for example in CI).

**Safety rails**, applied before anything is deleted:

- **Keep marker.** A resource tagged, or carrying a metadata/image-property
  key, matching `janitor:keep` (configurable via `[safety].keep_marker`) is
  never deleted — reported `protected` instead. The match is exact —
  case-sensitive and whitespace-sensitive, so `Janitor:Keep` or
  `janitor:keep ` will *not* protect a resource. There is deliberately no
  flag to bypass this: to unprotect a resource, remove the marker from it
  in the cloud, e.g. `openstack server unset --tag janitor:keep <id>` or
  `openstack volume unset --property janitor:keep <id>`.
- **Minimum age.** `--min-age-days` (or `[safety].min_age_days`, which the
  flag overrides) refuses to delete anything younger than the floor —
  reported `too-new`. A resource with no usable creation timestamp is
  treated as too new whenever a floor is set, since what can't be dated
  can't be proven old enough.

Both rails are evaluated once, when the plan is built (printed by the
preview), and that evaluation is what `clean` acts on — not a re-check
right before each delete. Tagging a resource with the keep marker *after*
its plan is printed will not save it; abort (answer "no", or Ctrl-C) and
re-run `clean` instead.

`janitor clean` exits `0` on a successful dry run, declined confirmation, or
execute, `1` if any resource was not deleted during execute — either the
deletion failed or the detector does not support cleaning (other resources
are still processed; failures are isolated per resource) — `2` for a missing
or unknown `--detector`, a missing/invalid `--config` file, an `--exclude`
ID that matched nothing, a negative `--min-age-days`, `--dry-run` combined
with `--yes`, or a prompt required on a non-interactive terminal, and `3`
if connecting to the cloud
or scanning it fails. `protected` and `too-new` resources are intentional
outcomes, not failures, and never affect the exit code.

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

Detection is always read-only — `janitor audit` never modifies anything. The
same detectors also know how to delete what they flag, but only
[`janitor clean --yes`](#cleaning) ever does so.

Resources without a parseable timestamp are never flagged by the age-based
detectors. Note that `orphaned-ports` and `unused-security-groups` have no age
threshold at all, so they can flag a resource created seconds ago — see the
warning under [Cleaning](#cleaning). `old-snapshots` and `shutoff-instances`
thresholds are configurable — see [Configuration](#configuration).

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

- More detectors for other orphaned/wasteful resource types.
