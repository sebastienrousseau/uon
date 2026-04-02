# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Tests for the Rust-backed persistent ZSP broker launcher."""

from __future__ import annotations

import importlib.util
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from uon.core import spawn_zsp_process


def _import_broker() -> Any:
    spec = importlib.util.spec_from_file_location(
        "uon_zsp_broker",
        str(Path(__file__).resolve().parents[2] / "scripts" / "uon_zsp_broker.py"),
    )
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def broker() -> Any:
    return _import_broker()


def test_launcher_delegates_to_rust_core(broker: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    mock_core = MagicMock()
    mock_core.run_zsp_broker.return_value = None
    monkeypatch.setitem(sys.modules, "uon", MagicMock(core=mock_core))

    assert broker.main() == 0
    mock_core.run_zsp_broker.assert_called_once_with()


@pytest.mark.skipif(os.name != "posix", reason="Unix socket broker requires POSIX")
def test_rust_broker_executes_round_trip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    socket_path = tmp_path / "zsp.sock"
    repo_root = Path(__file__).resolve().parents[2]
    broker_script = Path(__file__).resolve().parents[2] / "scripts" / "uon_zsp_broker.py"
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    src_path = str(repo_root / "src")
    env["PYTHONPATH"] = src_path if not existing_pythonpath else f"{src_path}:{existing_pythonpath}"
    env["UON_ZSP_SOCKET"] = str(socket_path)
    env["UON_ZSP_TARGET_UID"] = str(os.getuid())
    env["UON_ZSP_EXEC_GID"] = str(os.getgid())
    env["UON_ZSP_SOCKET_UID"] = str(os.getuid())
    env["UON_ZSP_SOCKET_GID"] = str(os.getgid())

    proc = subprocess.Popen(  # noqa: S603 - test launches the local broker entrypoint
        [sys.executable, str(broker_script)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            if socket_path.exists():
                break
            time.sleep(0.05)
        assert socket_path.exists()

        monkeypatch.setenv("UON_ZSP_SOCKET", str(socket_path))
        assert spawn_zsp_process("printf hello") == 0
        captured = capfd.readouterr()
        assert captured.out == "hello"
        assert captured.err == ""
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)
