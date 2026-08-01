"""Optional ``janitor.toml`` configuration.

Lets a cloud operator disable specific detectors, override per-detector
options (currently ``max_age_days``), and maintain a standing keep-list --
without a config file, behavior is unchanged from before this module
existed. Validation here is strict and fails closed: this project deletes
cloud resources, so a typo in the config must raise loudly rather than be
silently ignored.

May import :mod:`openstack_janitor.detectors` (to validate against the
registry); the reverse import must never happen.
"""

from __future__ import annotations

import inspect
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]

from openstack_janitor.detectors import ALL_DETECTORS

_CONFIG_FILENAME = "janitor.toml"
_ENV_VAR = "JANITOR_CONFIG"


class ConfigError(Exception):
    """Raised for a missing (when explicitly named), unparsable, or invalid config.

    Always carries a human-readable message naming the offending file and/or
    key -- callers should print ``str(exc)`` and exit, never let this
    propagate as a traceback.
    """


@dataclass(frozen=True)
class Config:
    """Parsed ``janitor.toml``, or the all-defaults config when none is found."""

    disabled: tuple[str, ...] = ()
    """Detector names to skip entirely."""

    detector_options: dict[str, dict[str, object]] = field(default_factory=dict)
    """Per-detector constructor kwargs, keyed by detector name."""

    exclude: tuple[str, ...] = ()
    """Standing keep-list of resource IDs, merged with ``clean --exclude``."""

    source: str = ""
    """Path this config was loaded from; "" means defaults (no file found)."""


def find_config_file() -> Path | None:
    """Locate ``janitor.toml``: ``$JANITOR_CONFIG``, then ``./janitor.toml``, then XDG.

    Search order:

    1. ``$JANITOR_CONFIG`` -- an explicitly named file. If set but the file
       does not exist, that is an error (:class:`ConfigError`), not a
       silent fall-through to the next candidate.
    2. ``./janitor.toml`` (current working directory).
    3. ``$XDG_CONFIG_HOME/janitor/janitor.toml``, falling back to
       ``~/.config/janitor/janitor.toml`` when ``XDG_CONFIG_HOME`` is unset.
       Used as-is on Windows too; no ``platformdirs`` dependency.

    Returns ``None`` when nothing is found at any of these locations.
    """
    env_path = os.environ.get(_ENV_VAR)
    if env_path:
        path = Path(env_path)
        if not path.is_file():
            raise ConfigError(f"{_ENV_VAR} is set to '{env_path}', but no such file exists.")
        return path

    cwd_path = Path.cwd() / _CONFIG_FILENAME
    if cwd_path.is_file():
        return cwd_path

    config_home = os.environ.get("XDG_CONFIG_HOME")
    base = Path(config_home) if config_home else Path.home() / ".config"
    xdg_path = base / "janitor" / _CONFIG_FILENAME
    if xdg_path.is_file():
        return xdg_path

    return None


def load_config(path: Path | None = None) -> Config:
    """Load and validate ``janitor.toml``.

    ``path=None`` auto-discovers via :func:`find_config_file`; when nothing
    is found, an all-defaults :class:`Config` is returned. Any TOML parse
    error or validation failure raises :class:`ConfigError`.
    """
    if path is None:
        path = find_config_file()
    if path is None:
        return Config()

    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"{path}: could not read file: {exc}") from exc

    return _parse(data, source=str(path))


def _parse(data: dict[str, Any], *, source: str) -> Config:
    registry = {cls.name: cls for cls in ALL_DETECTORS}
    valid_names = sorted(registry)

    valid_top = {"detectors", "clean"}
    unknown_top = sorted(set(data) - valid_top)
    if unknown_top:
        raise ConfigError(
            f"{source}: unknown top-level table(s): {', '.join(unknown_top)}. "
            f"Valid tables: {', '.join(sorted(valid_top))}."
        )

    detectors_table = data.get("detectors", {})
    if not isinstance(detectors_table, dict):
        raise ConfigError(f"{source}: [detectors] must be a table.")

    disabled = _parse_disabled(detectors_table, valid_names=valid_names, source=source)
    detector_options = _parse_detector_options(
        detectors_table, registry=registry, valid_names=valid_names, source=source
    )

    clean_table = data.get("clean", {})
    if not isinstance(clean_table, dict):
        raise ConfigError(f"{source}: [clean] must be a table.")
    exclude = _parse_exclude(clean_table, source=source)

    return Config(
        disabled=disabled,
        detector_options=detector_options,
        exclude=exclude,
        source=source,
    )


def _parse_disabled(
    detectors_table: dict[str, Any], *, valid_names: list[str], source: str
) -> tuple[str, ...]:
    disabled_raw = detectors_table.get("disabled", [])
    if not isinstance(disabled_raw, list):
        raise ConfigError(
            f"{source}: [detectors].disabled must be a list of detector names, "
            f"got {type(disabled_raw).__name__}."
        )
    non_str = [item for item in disabled_raw if not isinstance(item, str)]
    if non_str:
        raise ConfigError(
            f"{source}: [detectors].disabled must be a list of strings; "
            f"got non-string value(s): {non_str!r}."
        )
    unknown = sorted(name for name in disabled_raw if name not in valid_names)
    if unknown:
        raise ConfigError(
            f"{source}: [detectors].disabled names unknown detector(s): "
            f"{', '.join(unknown)}. Valid detectors: {', '.join(valid_names)}."
        )
    return tuple(disabled_raw)


def _parse_detector_options(
    detectors_table: dict[str, Any],
    *,
    registry: dict[str, type],
    valid_names: list[str],
    source: str,
) -> dict[str, dict[str, object]]:
    detector_options: dict[str, dict[str, object]] = {}
    for key, value in detectors_table.items():
        if key == "disabled":
            continue
        if not isinstance(value, dict):
            raise ConfigError(
                f"{source}: [detectors].{key} must be a table (e.g. "
                f"[detectors.{key}]), got {type(value).__name__}."
            )
        if key not in registry:
            raise ConfigError(
                f"{source}: [detectors.{key}] is not a registered detector. "
                f"Valid detectors: {', '.join(valid_names)}."
            )
        detector_options[key] = _validate_options(
            registry[key], value, source=source, detector_name=key
        )
    return detector_options


def _validate_options(
    detector_cls: type, options: dict[str, Any], *, source: str, detector_name: str
) -> dict[str, object]:
    """Restrict ``options`` to what ``detector_cls.__init__`` actually accepts.

    Keyword-only parameters (e.g. ``now`` on the age-based detectors) are
    deliberately excluded: those exist as test seams, not user-facing
    config options. ``*args``/``**kwargs`` are excluded too -- a detector
    with no ``__init__`` override inherits ``object.__init__``, whose
    signature is ``(self, /, *args, **kwargs)``; without this filter those
    would be accepted as bogus option names and later blow up at
    instantiation with a confusing ``TypeError``.
    """
    sig = inspect.signature(detector_cls.__init__)
    skip_kinds = (
        inspect.Parameter.KEYWORD_ONLY,
        inspect.Parameter.VAR_POSITIONAL,
        inspect.Parameter.VAR_KEYWORD,
    )
    accepted = sorted(
        name
        for name, param in sig.parameters.items()
        if name != "self" and param.kind not in skip_kinds
    )
    unknown = sorted(set(options) - set(accepted))
    if unknown:
        raise ConfigError(
            f"{source}: unknown option(s) for detector '{detector_name}': "
            f"{', '.join(unknown)}. Accepted options: {', '.join(accepted) or '(none)'}."
        )

    if "max_age_days" in options:
        value = options["max_age_days"]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise ConfigError(
                f"{source}: [detectors.{detector_name}].max_age_days must be a "
                f"number > 0, got {value!r}."
            )

    return dict(options)


def _parse_exclude(clean_table: dict[str, Any], *, source: str) -> tuple[str, ...]:
    unknown = sorted(set(clean_table) - {"exclude"})
    if unknown:
        raise ConfigError(
            f"{source}: unknown key(s) under [clean]: {', '.join(unknown)}. Valid keys: exclude."
        )
    exclude_raw = clean_table.get("exclude", [])
    if not isinstance(exclude_raw, list):
        raise ConfigError(
            f"{source}: [clean].exclude must be a list of resource IDs, "
            f"got {type(exclude_raw).__name__}."
        )
    non_str = [item for item in exclude_raw if not isinstance(item, str)]
    if non_str:
        raise ConfigError(
            f"{source}: [clean].exclude must be a list of resource ID strings; "
            f"got non-string value(s): {non_str!r}."
        )
    return tuple(exclude_raw)


__all__ = ["Config", "ConfigError", "find_config_file", "load_config"]
