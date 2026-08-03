"""Tests for `janitor.toml` discovery, parsing, and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from openstack_janitor.config import Config, ConfigError, find_config_file, load_config
from openstack_janitor.detectors import get_detectors
from openstack_janitor.detectors.snapshots import OldSnapshotsDetector


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path, monkeypatch):
    """Every test starts with no env vars and no real config file in the way."""
    monkeypatch.delenv("JANITOR_CONFIG", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.chdir(tmp_path)
    # Point HOME somewhere empty so a real ~/.config/janitor/janitor.toml on
    # the machine running the tests can never leak in.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --- find_config_file ------------------------------------------------------


def test_no_file_anywhere_returns_none(tmp_path) -> None:
    assert find_config_file() is None


def test_load_config_with_no_file_returns_defaults() -> None:
    config = load_config()

    assert config == Config()
    assert config.source == ""


def test_janitor_config_env_wins_over_cwd_file(tmp_path, monkeypatch) -> None:
    _write(tmp_path / "janitor.toml", "[clean]\nexclude = ['cwd-file']\n")
    explicit = _write(tmp_path / "explicit.toml", "[clean]\nexclude = ['env-file']\n")
    monkeypatch.setenv("JANITOR_CONFIG", str(explicit))

    found = find_config_file()

    assert found == explicit
    assert load_config().exclude == ("env-file",)


def test_janitor_config_env_set_but_missing_raises(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("JANITOR_CONFIG", str(tmp_path / "does-not-exist.toml"))

    with pytest.raises(ConfigError, match="JANITOR_CONFIG"):
        find_config_file()


def test_cwd_janitor_toml_is_found(tmp_path) -> None:
    cwd_file = _write(tmp_path / "janitor.toml", "[clean]\nexclude = ['x']\n")

    assert find_config_file() == cwd_file


def test_xdg_fallback_found_when_cwd_file_absent(tmp_path, monkeypatch) -> None:
    xdg_home = tmp_path / "xdg"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_home))
    xdg_file = _write(xdg_home / "janitor" / "janitor.toml", "[clean]\nexclude = ['x']\n")

    assert find_config_file() == xdg_file


def test_xdg_default_path_used_when_no_xdg_config_home(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    default_file = _write(tmp_path / ".config" / "janitor" / "janitor.toml", "[clean]\n")

    assert find_config_file() == default_file


# --- happy path --------------------------------------------------------


def test_happy_path_disabled_and_per_detector_options(tmp_path) -> None:
    _write(
        tmp_path / "janitor.toml",
        """
        [detectors]
        disabled = ["shutoff-instances"]

        [detectors.old-snapshots]
        max_age_days = 30

        [clean]
        exclude = ["vol-0001", "sg-0002"]
        """,
    )

    config = load_config()

    assert config.disabled == ("shutoff-instances",)
    assert config.detector_options == {"old-snapshots": {"max_age_days": 30}}
    assert config.exclude == ("vol-0001", "sg-0002")
    assert config.source.endswith("janitor.toml")

    detectors = get_detectors(config)
    names = [d.name for d in detectors]
    assert "shutoff-instances" not in names

    old_snapshots = next(d for d in detectors if d.name == "old-snapshots")
    assert isinstance(old_snapshots, OldSnapshotsDetector)
    assert old_snapshots.max_age_days == 30


# --- ConfigError cases ---------------------------------------------------


def test_invalid_toml_syntax_raises_config_error(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", "this is not valid toml [[[")

    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(path)


def test_unknown_top_level_table_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", "[bogus]\nfoo = 1\n")

    with pytest.raises(ConfigError, match="bogus"):
        load_config(path)


def test_unknown_key_in_detectors_table_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", "[detectors]\nnot-a-real-key = 1\n")

    with pytest.raises(ConfigError, match="not-a-real-key"):
        load_config(path)


def test_unknown_detector_in_disabled_list_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", '[detectors]\ndisabled = ["not-a-detector"]\n')

    with pytest.raises(ConfigError, match="not-a-detector"):
        load_config(path)


def test_unknown_detector_table_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", "[detectors.nope]\nmax_age_days = 5\n")

    with pytest.raises(ConfigError, match="nope"):
        load_config(path)


def test_unknown_option_for_detector_raises(tmp_path) -> None:
    """unattached-volumes takes no constructor options at all.

    Pins that the object.__init__(self, /, *args, **kwargs) fallback a
    detector with no __init__ override inherits does not leak "args"/
    "kwargs" into the accepted-options list -- the message must say the
    detector accepts nothing, not a confusing pair of bogus names.
    """
    path = _write(
        tmp_path / "janitor.toml",
        "[detectors.unattached-volumes]\nmax_age_days = 5\n",
    )

    with pytest.raises(ConfigError, match=r"Accepted options: \(none\)"):
        load_config(path)


def test_negative_max_age_days_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", "[detectors.old-snapshots]\nmax_age_days = -5\n")

    with pytest.raises(ConfigError, match="max_age_days"):
        load_config(path)


def test_zero_max_age_days_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", "[detectors.old-snapshots]\nmax_age_days = 0\n")

    with pytest.raises(ConfigError, match="max_age_days"):
        load_config(path)


def test_bool_max_age_days_raises(tmp_path) -> None:
    """bool is a subclass of int in Python -- must not sneak past the number check."""
    path = _write(tmp_path / "janitor.toml", "[detectors.old-snapshots]\nmax_age_days = true\n")

    with pytest.raises(ConfigError, match="max_age_days"):
        load_config(path)


def test_disabled_not_a_list_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", '[detectors]\ndisabled = "not-a-list"\n')

    with pytest.raises(ConfigError, match="disabled"):
        load_config(path)


def test_disabled_non_string_items_raise(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", "[detectors]\ndisabled = [1]\n")

    with pytest.raises(ConfigError, match="disabled"):
        load_config(path)


def test_disabled_mixed_string_and_non_string_items_raise(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", '[detectors]\ndisabled = ["old-snapshots", 1]\n')

    with pytest.raises(ConfigError, match="disabled"):
        load_config(path)


def test_exclude_not_a_list_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", '[clean]\nexclude = "not-a-list"\n')

    with pytest.raises(ConfigError, match="exclude"):
        load_config(path)


def test_exclude_non_string_items_raise(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", "[clean]\nexclude = [1, 2]\n")

    with pytest.raises(ConfigError, match="exclude"):
        load_config(path)


def test_exclude_nested_list_item_raises(tmp_path) -> None:
    """A nested list would otherwise crash `clean`'s set() union with an
    unhashable-type TypeError instead of a clean ConfigError."""
    path = _write(tmp_path / "janitor.toml", "[clean]\nexclude = [[1]]\n")

    with pytest.raises(ConfigError, match="exclude"):
        load_config(path)


def test_unknown_key_under_clean_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", "[clean]\nbogus = 1\n")

    with pytest.raises(ConfigError, match="bogus"):
        load_config(path)


def test_detectors_not_a_table_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", "detectors = 5\n")

    with pytest.raises(ConfigError, match="detectors"):
        load_config(path)


def test_clean_not_a_table_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", "clean = 5\n")

    with pytest.raises(ConfigError, match="clean"):
        load_config(path)


# --- [safety] --------------------------------------------------------------


def test_safety_defaults_when_no_file() -> None:
    config = load_config()

    assert config.keep_marker == "janitor:keep"
    assert config.min_age_days == 0.0


def test_safety_table_overrides_both_values(tmp_path) -> None:
    path = _write(
        tmp_path / "janitor.toml",
        '[safety]\nkeep_marker = "do-not-delete"\nmin_age_days = 14\n',
    )

    config = load_config(path)

    assert config.keep_marker == "do-not-delete"
    assert config.min_age_days == 14.0


def test_safety_not_a_table_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", "safety = 5\n")

    with pytest.raises(ConfigError, match="safety"):
        load_config(path)


def test_safety_keep_marker_non_string_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", "[safety]\nkeep_marker = 5\n")

    with pytest.raises(ConfigError, match="keep_marker"):
        load_config(path)


def test_safety_keep_marker_empty_string_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", '[safety]\nkeep_marker = ""\n')

    with pytest.raises(ConfigError, match="keep_marker"):
        load_config(path)


def test_safety_keep_marker_whitespace_only_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", '[safety]\nkeep_marker = "   "\n')

    with pytest.raises(ConfigError, match="keep_marker"):
        load_config(path)


def test_safety_keep_marker_padded_raises(tmp_path) -> None:
    """A padded marker would load "successfully" and then match no real tag
    -- resource markers never carry stray whitespace -- silently disabling
    the rail for anything actually tagged "janitor:keep"."""
    path = _write(tmp_path / "janitor.toml", '[safety]\nkeep_marker = "janitor:keep "\n')

    with pytest.raises(ConfigError, match="keep_marker"):
        load_config(path)


def test_safety_keep_marker_leading_whitespace_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", '[safety]\nkeep_marker = " janitor:keep"\n')

    with pytest.raises(ConfigError, match="keep_marker"):
        load_config(path)


def test_safety_min_age_days_bool_raises(tmp_path) -> None:
    """bool is a subclass of int in Python -- must not sneak past the number check."""
    path = _write(tmp_path / "janitor.toml", "[safety]\nmin_age_days = true\n")

    with pytest.raises(ConfigError, match="min_age_days"):
        load_config(path)


def test_safety_min_age_days_negative_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", "[safety]\nmin_age_days = -1\n")

    with pytest.raises(ConfigError, match="min_age_days"):
        load_config(path)


def test_safety_min_age_days_non_numeric_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", '[safety]\nmin_age_days = "soon"\n')

    with pytest.raises(ConfigError, match="min_age_days"):
        load_config(path)


def test_safety_min_age_days_zero_is_allowed(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", "[safety]\nmin_age_days = 0\n")

    config = load_config(path)

    assert config.min_age_days == 0.0


def test_unknown_key_under_safety_raises(tmp_path) -> None:
    path = _write(tmp_path / "janitor.toml", "[safety]\nbogus = 1\n")

    with pytest.raises(ConfigError, match="bogus"):
        load_config(path)
