# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-07-25

### Changed

- **Breaking — `janitor clean` no longer previews by default.** In 0.3.x,
  `janitor clean -d <detector>` was a dry run that deleted nothing. It now
  prints the plan, asks for confirmation, and deletes on `yes`. Use
  `--dry-run` (or `--dry`) for the old preview-and-exit behaviour. `--yes`
  still deletes without prompting. If you have scripts or habits built on
  bare `clean` being safe, add `--dry-run`.
  - Answering anything but yes, or pressing Enter, deletes nothing.
  - `clean` refuses to prompt when stdin is not a terminal, so it cannot
    delete unattended: pass `--yes` or `--dry-run` in CI. Exits `2`.
  - `--dry-run` together with `--yes` is rejected with exit `2`.
- Detection now runs **once per invocation**, and the plan you confirm is the
  set that gets deleted. Previously the preview and the `--yes` run were two
  independent detection passes, so a resource created in between could be
  deleted without ever appearing in the reviewed table. Thanks to @pczarnik
  for the report and the fix (#4).

### Added

- `audit` shows a **Detector** column so the name can be copied into
  `clean -d`. Hidden when a single `--detector` is given, since it is then
  redundant. `Finding` gained a `detector` field, which also adds a
  `detector` key to `--format json` output. Thanks @pczarnik (#5).
- `audit --long` / `-l` prints all extra columns, exposing the per-detector
  detail that `json` and `html` already carried (#7).

### Fixed

- Table output is no longer clamped to 80 columns when stdout is not a
  terminal. Rich's non-terminal fallback truncated resource IDs mid-string,
  so IDs from `janitor audit | less` could not be pasted into
  `clean --exclude`. Terminals are unchanged, and an explicit `COLUMNS`
  still wins (#6).

## [0.3.1] - 2026-07-25

### Fixed

- `audit` and `clean` now exit `3` with a readable error — instead of an
  unhandled traceback and exit `1` — when the cloud is unreachable, DNS
  resolution fails, credentials are wrong, or the token expires. These
  failures are raised by keystoneauth1, whose exceptions are not
  `SDKException` subclasses, so the existing handlers never caught them.
  Affects 0.1.0 through 0.3.0.
- `clean` escapes cloud-supplied text in its connection and scan error
  messages, matching `audit`. A real DNS-failure message contains
  `[Errno 11001]`, which was otherwise parsed as terminal markup.

### Changed

- `keystoneauth1` is now a declared dependency. It was already installed as a
  transitive dependency of openstacksdk; the CLI imports it directly.

## [0.3.0] - 2026-07-24

### Added

- `janitor clean` — deletes the resources the detectors flag. **Dry run by
  default**: without `--yes` nothing is touched, it only previews. Options:
  `--cloud/-c`, `--detector/-d`, `--exclude/-e`, `--yes/-y`.
- Safety behaviour built into `clean`:
  - `--detector` is **required**, so one command can never delete across all
    seven resource types at once.
  - `--exclude` takes resource IDs and **aborts the run** if a value matches
    no finding, so a typo cannot silently delete what it was meant to protect.
  - Findings are re-detected immediately before acting; a scan failure deletes
    nothing.
  - Failures are isolated per resource, and the report is always printed —
    including on Ctrl-C — so there is never a deletion without a record.
  - A detector that does not implement deletion is reported as `unsupported`
    rather than treated as deleted.
- `Detector.clean` for each of the seven detectors, using `ignore_missing=True`
  so a concurrently-deleted resource is a no-op.

### Changed

- Successful deletions report as `requested`, not `deleted`: OpenStack deletes
  are asynchronous, so an accepted call means the delete is under way.
- Terminal output escapes cloud-supplied text (resource names, IDs, error
  messages), which previously could be parsed as terminal markup and abort the
  report.
- `audit` now distinguishes a connection failure from a scan failure in its
  error message (both still exit 3).

## [0.2.0] - 2026-07-22

### Added

- `orphan-snapshot-images` detector — flags Glance images whose
  `block_device_mapping` references a Cinder volume snapshot that no longer
  exists (hidden images included). Detector count is now seven.
- `janitor detectors` command — lists every registered detector and its
  description without connecting to a cloud.
- Short options for `janitor audit`: `-c/--cloud`, `-d/--detector`,
  `-f/--format`, `-h/--help`.

Thanks to @pczarnik for all three contributions.

## [0.1.1] - 2026-07-14

### Changed

- Lowered the minimum supported Python from 3.11 to 3.9. On older
  interpreters pip automatically resolves the newest compatible
  openstacksdk. CI now tests Python 3.9 through 3.13.

### Added

- Standalone Linux x86_64 binary attached to GitHub releases. Built against
  glibc 2.28, so it runs on RHEL 8-era hosts without any Python install.
- Install troubleshooting notes for old distro-patched pip versions.

## [0.1.0] - 2026-07-14

First release: the complete read-only audit story.

### Added

- `janitor audit` command that scans an OpenStack cloud and reports
  orphaned/wasteful resources, with cron-friendly exit codes
  (`0` clean, `1` findings, `2` unknown detector, `3` connection failure).
- Six read-only detectors:
  - `unattached-volumes` — volumes in `available` status with no attachments.
  - `unassociated-floating-ips` — floating IPs not associated with any port.
  - `orphaned-ports` — ports with no device owner and no device id.
  - `old-snapshots` — snapshots older than a threshold (default 90 days).
  - `shutoff-instances` — instances SHUTOFF for at least a threshold
    (default 30 days, conservative lower bound).
  - `unused-security-groups` — groups with no port attachment and no
    `remote_group_id` reference; the per-project `default` group is skipped.
- `--format table|json|html` report output.
- `--cloud` (named cloud from `clouds.yaml`) and repeatable `--detector`
  selection.
- Non-admin fallback: detectors that use admin-only `all_projects` listings
  retry scoped to the caller's own project when forbidden.

[0.4.0]: https://github.com/mabunemeh/openstack-janitor/releases/tag/v0.4.0
[0.3.1]: https://github.com/mabunemeh/openstack-janitor/releases/tag/v0.3.1
[0.3.0]: https://github.com/mabunemeh/openstack-janitor/releases/tag/v0.3.0
[0.2.0]: https://github.com/mabunemeh/openstack-janitor/releases/tag/v0.2.0
[0.1.1]: https://github.com/mabunemeh/openstack-janitor/releases/tag/v0.1.1
[0.1.0]: https://github.com/mabunemeh/openstack-janitor/releases/tag/v0.1.0
