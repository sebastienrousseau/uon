"""Tests for src.utils.config — platform config dirs, Target, TargetStore."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.utils.config import Target, TargetStore, _config_dir

# ── _config_dir() ─────────────────────────────────────────────────────

class TestConfigDir:
    """Platform-dependent config directory resolution."""

    def test_darwin(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr("src.utils.config.sys.platform", "darwin")
        monkeypatch.setattr("src.utils.config.Path.home", lambda: tmp_path)
        result = _config_dir()
        assert result == tmp_path / "Library" / "Application Support" / "uon"
        assert result.is_dir()

    def test_win32(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr("src.utils.config.sys.platform", "win32")
        appdata = tmp_path / "AppData" / "Roaming"
        appdata.mkdir(parents=True)
        monkeypatch.setenv("APPDATA", str(appdata))
        result = _config_dir()
        assert result == appdata / "uon"
        assert result.is_dir()

    def test_win32_no_appdata(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr("src.utils.config.sys.platform", "win32")
        monkeypatch.delenv("APPDATA", raising=False)
        monkeypatch.setattr("src.utils.config.Path.home", lambda: tmp_path)
        result = _config_dir()
        assert result == tmp_path / "uon"

    def test_linux_xdg(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr("src.utils.config.sys.platform", "linux")
        xdg = tmp_path / "xdg"
        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
        result = _config_dir()
        assert result == xdg / "uon"
        assert result.is_dir()

    def test_linux_default(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr("src.utils.config.sys.platform", "linux")
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.setattr("src.utils.config.Path.home", lambda: tmp_path)
        result = _config_dir()
        assert result == tmp_path / ".config" / "uon"


# ── Target dataclass ──────────────────────────────────────────────────

class TestTarget:
    def test_defaults(self) -> None:
        t = Target(alias="x", host="1.2.3.4")
        assert t.port == 22
        assert t.user == "root"
        assert t.credential_ids == []

    def test_from_dict_full(self) -> None:
        t = Target.from_dict({
            "alias": "prod",
            "host": "10.0.0.1",
            "port": 2222,
            "user": "deploy",
            "credential_ids": ["abc", "def"],
        })
        assert t.alias == "prod"
        assert t.port == 2222
        assert t.credential_ids == ["abc", "def"]

    def test_from_dict_minimal(self) -> None:
        t = Target.from_dict({"alias": "box", "host": "h"})
        assert t.port == 22
        assert t.user == "root"
        assert t.credential_ids == []


# ── TargetStore ───────────────────────────────────────────────────────

class TestTargetStore:
    def test_empty(self, target_store: TargetStore) -> None:
        assert target_store.list_targets() == []
        assert target_store.get("nope") is None

    def test_add_and_get(self, target_store: TargetStore, sample_target: Target) -> None:
        target_store.add(sample_target)
        got = target_store.get("dev")
        assert got is not None
        assert got.host == "192.168.1.10"

    def test_overwrite(self, target_store: TargetStore, sample_target: Target) -> None:
        target_store.add(sample_target)
        updated = Target(alias="dev", host="10.0.0.99")
        target_store.add(updated)
        assert target_store.get("dev") is not None
        assert target_store.get("dev").host == "10.0.0.99"  # type: ignore[union-attr]

    def test_list(self, target_store: TargetStore) -> None:
        target_store.add(Target(alias="a", host="1"))
        target_store.add(Target(alias="b", host="2"))
        assert len(target_store.list_targets()) == 2

    def test_remove_existing(self, target_store: TargetStore, sample_target: Target) -> None:
        target_store.add(sample_target)
        assert target_store.remove("dev") is True
        assert target_store.get("dev") is None

    def test_remove_missing(self, target_store: TargetStore) -> None:
        assert target_store.remove("ghost") is False

    def test_persistence_round_trip(
        self, tmp_targets_file: Path, sample_target: Target
    ) -> None:
        store1 = TargetStore(path=tmp_targets_file)
        store1.add(sample_target)

        store2 = TargetStore(path=tmp_targets_file)
        got = store2.get("dev")
        assert got is not None
        assert got.host == sample_target.host
        assert got.user == sample_target.user
