"""Shared fixtures for the uon test suite."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import click.testing
import pytest

from uon.utils.config import Target, TargetStore


@pytest.fixture
def tmp_targets_file(tmp_path: Path) -> Path:
    """Return a path to a non-existent targets.json inside *tmp_path*."""
    return tmp_path / "targets.json"


@pytest.fixture
def target_store(tmp_targets_file: Path) -> TargetStore:
    """Return a TargetStore backed by a temporary file."""
    return TargetStore(path=tmp_targets_file)


@pytest.fixture
def sample_target() -> Target:
    """A convenient Target with sensible defaults."""
    return Target(alias="dev", host="192.168.1.10", port=22, user="admin")


@pytest.fixture
def mock_paramiko_client() -> MagicMock:
    """A MagicMock standing in for ``paramiko.SSHClient``."""
    client = MagicMock()
    stdout_chan = MagicMock()
    stdout_chan.recv_exit_status.return_value = 0
    stdout_mock = MagicMock()
    stdout_mock.read.return_value = b"hello\n"
    stdout_mock.channel = stdout_chan
    stderr_mock = MagicMock()
    stderr_mock.read.return_value = b""
    client.exec_command.return_value = (MagicMock(), stdout_mock, stderr_mock)
    return client


@pytest.fixture
def cli_runner() -> click.testing.CliRunner:
    """A Click test runner."""
    return click.testing.CliRunner()


@pytest.fixture
def isolate_store(tmp_targets_file: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Monkeypatch ``TargetStore`` in ``src.cli`` to use a temp path.

    Returns the temp file path for assertions.
    """
    _orig_init = TargetStore.__init__

    def _patched_init(self: TargetStore, path: Path = tmp_targets_file) -> None:
        _orig_init(self, path)

    monkeypatch.setattr(TargetStore, "__init__", _patched_init)
    return tmp_targets_file
