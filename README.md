# openstack-janitor

[![CI](https://github.com/mabunemeh/openstack-janitor/actions/workflows/ci.yml/badge.svg)](https://github.com/mabunemeh/openstack-janitor/actions/workflows/ci.yml)

A CLI for OpenStack operators that finds orphaned and wasteful resources
(unattached volumes, old snapshots, unused floating IPs, ports and security
groups, long-shutoff instances, broken snapshot images) and can delete them.

`janitor audit` only reads. `janitor clean` deletes, and deletes are
irreversible.

## Install

Requires Python 3.9 or later.

```sh
pipx install openstack-janitor
# or
pip install openstack-janitor
```

There is also a standalone Linux binary that needs no Python. It is built
against glibc 2.28, so it runs on RHEL 8-era hosts whose system Python is too
old for the package:

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

On old distro pips (for example pip 22.0 on Ubuntu 22.04), a source install
can fail with `No module named 'packaging.licenses'`. Use a fresh venv with
an upgraded pip: `python3 -m venv .venv && .venv/bin/pip install -U pip`.
Installing from PyPI is unaffected.

## Authentication

Authentication goes through
[openstacksdk](https://docs.openstack.org/openstacksdk/latest/), so anything
it accepts works here:

- a named cloud from `clouds.yaml`, with `--cloud my-cloud` or `OS_CLOUD`
- the standard `OS_*` variables (`OS_AUTH_URL`, `OS_USERNAME`,
  `OS_PASSWORD`, `OS_PROJECT_NAME`, ...) when no cloud is named

See the openstacksdk
[configuration docs](https://docs.openstack.org/openstacksdk/latest/user/config/configuration.html)
for the resolution order and file locations.

## Auditing

```sh
janitor detectors                                  # list detector names; no cloud needed
janitor audit                                      # run every detector
janitor audit -c my-cloud
janitor audit -d unattached-volumes -d orphaned-ports
janitor audit -f json > findings.json
janitor audit -f html > report.html
janitor audit --long                               # add a column of per-detector details
```

Options: `-c`/`--cloud`, `-d`/`--detector` (repeatable), `-C`/`--config`,
`-f`/`--format` (`table`, `json` or `html`), `-l`/`--long`.

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

The Detector column is left out when you run a single `-d`.

Exit codes, the same for every format:

| Code | Meaning |
| --- | --- |
| 0 | No findings |
| 1 | Findings reported (usable as a cron or CI check) |
| 2 | Unknown `--detector`, missing or invalid config file, or every detector disabled in config |
| 3 | Connecting to or scanning the cloud failed |

## Detectors

| Name | Flags |
| --- | --- |
| `unattached-volumes` | Volumes in `available` status with no attachments. |
| `unattached-volumes-no-snapshots` | The subset of `unattached-volumes` that also has no dependent snapshots. Cinder refuses to delete a volume that still has snapshots, so this is the set `clean` can actually remove. Handy for the unnamed volumes left behind after removing VM snapshots. |
| `unassociated-floating-ips` | Floating IPs not associated with any port. |
| `orphaned-ports` | Ports with no device owner and no device ID. DHCP, router and load balancer ports always have one, so they are never flagged; a pre-created port waiting to be attached will be. |
| `old-snapshots` | Volume snapshots older than 90 days (configurable). |
| `shutoff-instances` | Instances in `SHUTOFF` whose last update is older than 30 days (configurable). The Compute API has no "shut off since" field, so this can under-report but not over-report. |
| `unused-security-groups` | Security groups attached to no port and not referenced as a `remote_group_id` by any rule. Each project's `default` group is skipped. |
| `orphan-snapshot-images` | Glance images, including hidden ones, whose `block_device_mapping` points at a volume snapshot that no longer exists. |

An unattached volume with no snapshots is reported by both volume detectors,
so a default audit lists it twice. Run one with `-d`, or disable one in
config.

The age-based detectors skip resources without a parseable timestamp.
`orphaned-ports` and `unused-security-groups` have no age threshold, so they
can flag something created seconds ago.

## Cleaning

```sh
janitor clean -d unattached-volumes --dry-run         # print the plan, delete nothing
janitor clean -d unattached-volumes                   # print the plan, prompt, then delete
janitor clean -d unattached-volumes --yes             # print the plan and delete without prompting
janitor clean -d unattached-volumes -e vol-0001 --yes # keep specific resource IDs
```

`clean` runs detection once, prints the plan, and deletes exactly that plan.
`--detector` is required, so one command cannot delete across every resource
type. Other options: `-e`/`--exclude` (repeatable), `--min-age-days`,
`--dry-run` (alias `--dry`), `-y`/`--yes`, plus `-c` and `-C` as for
`audit`.

Before you delete:

- `orphaned-ports` and `unused-security-groups` will flag resources that are
  mid-provisioning or in use by a running CI job. Keep `-d` narrow and use
  `--min-age-days` or the keep marker.
- Cleaning can create new findings. Deleting a shutoff instance leaves its
  volumes unattached; deleting snapshots orphans images built from them.
  Read each plan instead of looping `--yes`.
- `--exclude` takes resource IDs, not names. An ID that matches no finding
  aborts the run, so a typo cannot delete what it was meant to protect.
- Deletes are asynchronous. A success means OpenStack accepted the request;
  check with `janitor audit` afterwards.
- Without a TTY (in CI, for example), pass `--yes` or `--dry-run`. `clean`
  will not prompt.

Two safety rails are applied when the plan is built:

- **Keep marker.** A resource with a tag, metadata key or image property key
  equal to `janitor:keep` (set with `[safety].keep_marker`) is never deleted
  and shows as `protected`. The match is exact and case-sensitive. There is
  no flag to override it; remove the marker in the cloud instead, for
  example `openstack server unset --tag janitor:keep <id>` or
  `openstack volume unset --property janitor:keep <id>`.
- **Minimum age.** `--min-age-days` (or `[safety].min_age_days`) skips
  anything younger than the floor and shows it as `too-new`. With a floor
  set, a resource with no usable creation time counts as too new.

The rails are not re-checked before each delete. Adding the keep marker after
the plan is printed will not save a resource; answer no or press Ctrl-C and
run `clean` again.

`clean` exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Dry run, declined prompt, or every delete accepted |
| 1 | At least one resource was not deleted (the delete failed, or the detector cannot clean); the rest are still processed |
| 2 | Missing or unknown `--detector`, missing or invalid config file, unmatched `--exclude` ID, negative `--min-age-days`, `--dry-run` with `--yes`, or a prompt needed without a TTY |
| 3 | Connecting to or scanning the cloud failed |

`protected` and `too-new` resources do not affect the exit code.

## Configuration

Settings live in `janitor.toml`. Pass a path with `-C`/`--config`, or the
first of these that exists is used: `$JANITOR_CONFIG`, `./janitor.toml`,
`$XDG_CONFIG_HOME/janitor/janitor.toml` (default
`~/.config/janitor/janitor.toml`). Unknown keys are an error.

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

An explicit `-d` runs a detector even if config disables it. `--exclude` adds
to `clean.exclude`, and unlike `--exclude`, a config entry that matches
nothing is not an error. `--min-age-days` overrides `[safety].min_age_days`.

## Development

```sh
pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy
pytest
```

## License

Apache 2.0. See [LICENSE](LICENSE).
