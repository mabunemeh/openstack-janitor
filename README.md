# openstack-janitor

A CLI that audits an OpenStack cloud for orphaned and wasteful resources.

**Status: early development.** The first detector (unattached volumes) is
working; more detectors and a `clean` command are coming — see
[Roadmap](#roadmap).

## Install

From source:

```sh
git clone <this repo>
cd openstack-janitor
pip install -e .
```

Publishing to PyPI (`pip install openstack-janitor`) and a `pipx`-friendly
release are planned once there's more than one detector.

## Usage

```sh
janitor audit
janitor audit --cloud my-cloud
janitor audit --detector unattached-volumes
```

Example output when orphaned volumes are found:

```
$ janitor audit --cloud my-cloud
              openstack-janitor findings
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Detector/Type ┃ ID        ┃ Name    ┃ Project ┃ Reason                       ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ volume        │ a1b2c3d4… │ old-db  │ proj-1  │ volume is unattached         │
│               │           │         │         │ (status=available)          │
└───────────────┴───────────┴─────────┴─────────┴──────────────────────────────┘
$ echo $?
1
```

`janitor audit` exits `0` when nothing is found, `1` when findings were
reported (so it's safe to wire into a cron job or CI check), `2` if an
unknown `--detector` name is given, and `3` if connecting to the cloud
fails.

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

- More detectors: floating IPs, unused ports, orphaned snapshots, long-shutoff
  instances, unused security groups.
- A `clean` command with a `--dry-run` default and explicit `--yes` to act.
- `janitor.toml` for per-cloud configuration (which detectors run, age
  thresholds, exclusions).
- Safety rails: tagging/exclusion lists so resources can be marked "do not
  touch" before `clean` ever deletes anything.
- JSON/HTML report output.
