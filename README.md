# openstack-janitor

[![CI](https://github.com/mabunemeh/openstack-janitor/actions/workflows/ci.yml/badge.svg)](https://github.com/mabunemeh/openstack-janitor/actions/workflows/ci.yml)

A CLI that audits an OpenStack cloud for orphaned and wasteful resources.

**Status: early development.** Seven detectors and a `clean` command are
working — see [Detectors](#detectors) and [Cleaning](#cleaning); more
detectors and safety rails are coming — see [Roadmap](#roadmap).

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

- **Some detectors have no age threshold.** `orphaned-ports` and
  `unused-security-groups` flag by state alone, so a port or group created
  seconds ago — mid-provisioning, mid-CI-run — is a finding and will be
  deleted. Until tag/age rails land, keep `--detector` narrow.
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

Tag/age safety rails (e.g. a `janitor:keep` marker) are on the
[roadmap](#roadmap) but not implemented yet.

`janitor clean` exits `0` on a successful dry run, declined confirmation, or
execute, `1` if any resource was not deleted during execute — either the
deletion failed or the detector does not support cleaning (other resources
are still processed; failures are isolated per resource) — `2` for a missing
or unknown `--detector`, an `--exclude` ID that matched nothing,
`--dry-run` combined with `--yes`, or a prompt required on a non-interactive
terminal, and `3` if connecting to the cloud or scanning it fails.

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
warning under [Cleaning](#cleaning). Thresholds become configurable once
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

- `janitor.toml` for per-cloud configuration (which detectors run, age
  thresholds, exclusions).
- Safety rails: a `janitor:keep` tag (or similar) so resources can be marked
  "do not touch" before `clean` ever deletes anything, beyond today's
  `--exclude` flag and dry-run review.
